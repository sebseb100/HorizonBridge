// SPDX-License-Identifier: UNLICENSED

//Defining program code
pragma solidity 0.7.3;
pragma experimental ABIEncoderV2;

//Importing all dependencies
import "./HarmonyParser.sol";
import "./lib/SafeCast.sol";
import "@openzeppelin/contracts-upgradeable/math/SafeMathUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
// import "openzeppelin-solidity/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
// import "openzeppelin-solidity/contracts/proxy/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/Initializable.sol";

//Defining the HarmonyLightClient smart contract and inheriting the contracts from 3 files that containt
//Initializable, PausableUpgradable, AccessControlUpgradable which all describe their purposes
contract HarmonyLightClient is
    Initializable,
    PausableUpgradeable,
    AccessControlUpgradeable
{

    using SafeCast for *;
    using SafeMathUpgradeable for uint256;

    //Initializing a struct which is sort of an object 
    //Within the brackets all of the variables attached to the BlockHeader struct are initialized
    //The BlockHeader is the main data structure that the Light-Client will be transporting
    struct BlockHeader 
    {
        bytes32 parentHash;
        bytes32 stateRoot;
        bytes32 transactionsRoot;
        bytes32 receiptsRoot;
        uint256 number;
        uint256 epoch;
        uint256 shard;
        uint256 time;
        bytes32 mmrRoot;
        bytes32 hash;
    }

    //While transporing the blockheader there are checkpoints reached 
    //Creating an event CheckPoint 
    //An event in Solidity means " An event allows a contract to log a change of state to the blockchain 
    //in a specific format to allow the Ethereum VM to easily retrieve and filter them, and an event can 
    //carry with it data about the state change"

    event CheckPoint(
        bytes32 stateRoot,
        bytes32 transactionsRoot,
        bytes32 receiptsRoot,
        uint256 number,
        uint256 epoch,
        uint256 shard,
        uint256 time,
        bytes32 mmrRoot,
        bytes32 hash
    );

    //Two instances of the Blockheader struct meaning initializing two variables of type BlockHeader
    BlockHeader firstBlock;
    BlockHeader lastCheckPointBlock;

    // epoch to block numbers, as there could be >=1 mmr entries per epoch
    mapping(uint256 => uint256[]) epochCheckPointBlockNumbers;

    // block number to BlockHeader
    mapping(uint256 => BlockHeader) checkPointBlocks;

    mapping(uint256 => mapping(bytes32 => bool)) epochMmrRoots;

    //relayer threshold integer
    uint8 relayerThreshold;

    //Three events to keep track of state changes we're passing in the address of the relayer into 
    //RelayerAdded and RelayerRemoved so when these events are called they can be executed whenever
    //A relayer is needed or no longer needed 
    //Also the RelayerThresholdChanged allows an integer "newThreshold" to be passed in as a param
    event RelayerThresholdChanged(uint256 newThreshold);
    event RelayerAdded(address relayer);
    event RelayerRemoved(address relayer);

    //defining a public constant of type bytes32 called RELAYER_ROLE assigned to the hashing func executing on "RELAYER-ROLE"
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    //In solidity "modifier" is used to modify the behavior of an already existing function
    //You can also use it to ensure particular rules are in order pre-execution
    //The following functions come from the imported  Initializable.sol, PausableUpgradeable.sol, AccessControlUpgradeable.sol

    //Modifying the onlyAdmin function to reuire the parameters to contain role of DEFAULT_ADMIN_ROLE and the message sender: msg.sender
    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "sender doesn't have admin role");
        _;
    }

    //Modifying the onlyRelayers to require that the hasRole contains RELAYER_ROLE, and msg.sender 
    modifier onlyRelayers() {
        require(hasRole(RELAYER_ROLE, msg.sender), "sender doesn't have relayer role");
        _;
    }

    //Defining a function adminPauseLightClient as an external function containing functionality adminPauseLightClient 
    //In the function is a call to another private function taken from PausableUpgradable.sol 
    //So in a sense here were just carefully inheriting the use of other function we imported 
    //This function pauses the light client
    function adminPauseLightClient() external onlyAdmin {
        _pause();
    }

    //This function is responsible for unpausing the light client
    //You'll notice the private function _unpause() called within it 
    function adminUnpauseLightClient() external onlyAdmin {
        _unpause();
    }

    //This function called renounceAdmin accepts the addrress of newAdmin again tied to the modified external function onlyAdmin
    //The function requires that the msg.sender isn't the new administrator since it cannot renounce itself
    //The grantRole function accepts the DEFAULT_ADMIN_ROLE and grants the newAdmin those privledges
    //The renounce role declares the abandonment of the DEFAULT_ADMIN_ROLE since newAdmin is here now!
    function renounceAdmin(address newAdmin) external onlyAdmin {
        require(msg.sender != newAdmin, 'cannot renounce self');
        grantRole(DEFAULT_ADMIN_ROLE, newAdmin);
        renounceRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    //Function that changes the relayer threshold by accepting a new threshold again tied to the privledges of the Admin
    //The relayerThreshold is assigned to the newThreshold conver to a new data type Uint8
    //emit emits/releases the change. So it's basically calling into action the change just made
    function adminChangeRelayerThreshold(uint256 newThreshold) external onlyAdmin {
        relayerThreshold = newThreshold.toUint8();
        emit RelayerThresholdChanged(newThreshold);
    }

    //Another onlyAdmin operation called adminAddRelayer which allows the contract to add a relayer
    //It accepts a "address" data type paramater, its required that NOT RELAYER_ROLE is already the relayerAddress
    //Essentially hasRole is saying the Role in the first param is the second param
    //Then the role is granted as long as the RELAYER_ROLE isn't the relayerAddress passed into the function
    //Finally we emit this action and officially add the relayer relayerAddress
    function adminAddRelayer(address relayerAddress) external onlyAdmin {
        require(!hasRole(RELAYER_ROLE, relayerAddress), "addr already has relayer role!");
        grantRole(RELAYER_ROLE, relayerAddress);
        emit RelayerAdded(relayerAddress);
    }

    //Very similar to comments above, please reffer to those
    //This functionality operatable to external onlyAdmin does the precise opposite of the previous funciton
    //Instead the relayerAddress passed in will now be remove and the require statement will check to see
    //that the relayerAddress passed in is already presently the RELAYER_ROLE otherwise the function can't execute removal
    //revokeRole is called to revoke the roll/remove the placeholder for RELAYER_ROLE
    //emit makes it real in the smart contract scope
    function adminRemoveRelayer(address relayerAddress) external onlyAdmin {
        require(hasRole(RELAYER_ROLE, relayerAddress), "addr doesn't have relayer role!");
        revokeRole(RELAYER_ROLE, relayerAddress);
        emit RelayerRemoved(relayerAddress);
    }

    //defining a function that accepts firstRlpHeader param (bytes) present to the memory within the contract
    //address array held in contract memory called initialRelayers
    //finally a integer initialRelayerThreshold setting the initial threshold
    function initialize(
        bytes memory firstRlpHeader,
        address[] memory initialRelayers,
        uint8 initialRelayerThreshold
    ) external initializer {
        HarmonyParser.BlockHeader memory header = HarmonyParser.toBlockHeader(
            firstRlpHeader
        );
        
        //remember firstBlock is an instance of the Blockheader struct 
        //it's inheiriting the variables here (think object oriented programming)
        firstBlock.parentHash = header.parentHash;
        firstBlock.stateRoot = header.stateRoot;
        firstBlock.transactionsRoot = header.transactionsRoot;
        firstBlock.receiptsRoot = header.receiptsRoot;
        firstBlock.number = header.number;
        firstBlock.epoch = header.epoch;
        firstBlock.shard = header.shardID;
        firstBlock.time = header.timestamp;
        //conversion to Bytes32 
        firstBlock.mmrRoot = HarmonyParser.toBytes32(header.mmrRoot);
        firstBlock.hash = header.hash;
        
        epochCheckPointBlockNumbers[header.epoch].push(header.number);
        checkPointBlocks[header.number] = firstBlock;

        epochMmrRoots[header.epoch][firstBlock.mmrRoot] = true;

        relayerThreshold = initialRelayerThreshold;
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);

        //indexing through the initialRelayers array granting the roles of the initrialRelayer[index] to RELAYER_ROLE
        //NOW WE HAVEA SET OF RELAYERS!
        for (uint256 i; i < initialRelayers.length; i++) {
            grantRole(RELAYER_ROLE, initialRelayers[i]);
        }

    }

    //To submit the checkpoint a variable held in memory of type bytes is accepted 'rlpHeader' this is operatable as long as 
    //it is onlyRelayers and whenNotPaused
    //The blockheader of HarmonyParser as header 
    //header is assigned to the blockheader of rlpHeader paramater utilizing HarmonyParser
    function submitCheckpoint(bytes memory rlpHeader) external onlyRelayers whenNotPaused {
        HarmonyParser.BlockHeader memory header = HarmonyParser.toBlockHeader(
            rlpHeader
        );

        //chekcPointBlock is BlockHeader object held in contract memory;
        BlockHeader memory checkPointBlock;
        
        checkPointBlock.parentHash = header.parentHash;
        checkPointBlock.stateRoot = header.stateRoot;
        checkPointBlock.transactionsRoot = header.transactionsRoot;
        checkPointBlock.receiptsRoot = header.receiptsRoot;
        checkPointBlock.number = header.number;
        checkPointBlock.epoch = header.epoch;
        checkPointBlock.shard = header.shardID;
        checkPointBlock.time = header.timestamp;
        checkPointBlock.mmrRoot = HarmonyParser.toBytes32(header.mmrRoot);
        checkPointBlock.hash = header.hash;
        
        
        epochCheckPointBlockNumbers[header.epoch].push(header.number);
        checkPointBlocks[header.number] = checkPointBlock;

        epochMmrRoots[header.epoch][checkPointBlock.mmrRoot] = true;

        //making the execution present to thee contract
        //passing in all of the inherited variables from header into the CheckPoint function
        //it accepts the state root, transaction root, receipient root, block numberm, epoch, shard, time, mimic root, and hash
        emit CheckPoint(
            checkPointBlock.stateRoot,
            checkPointBlock.transactionsRoot,
            checkPointBlock.receiptsRoot,
            checkPointBlock.number,
            checkPointBlock.epoch,
            checkPointBlock.shard,
            checkPointBlock.time,
            checkPointBlock.mmrRoot,
            checkPointBlock.hash
        );
    }

    //function getLatestCheckPint accepts the blockNumber and epoch, both integers
    //the function is public view
    //the function returns BlockHeader memory checkPoint
    
    function getLatestCheckPoint(uint256 blockNumber, uint256 epoch)
        public
        view
        returns (BlockHeader memory checkPointBlock)
    {
    //the funciton requires that the length of the array epochCheckPointBlockNumbers is greater than zero otherwise there wouldn't be any checkpoints to retrieve
        require(
            epochCheckPointBlockNumbers[epoch].length > 0,
            "no checkpoints for epoch"
        );
    
    //indexing one at a time until the checkPointBlockNumbers.lenght is reached setting CheckPintBlockNumber to that index
    //if the checkpointBlockNumber is greater than the blockNumber passed into the function and less than the nearest blockNumber
    //we assign nearest to the checkPintBlockNumber, otherise we just set the checkPointBlock to the nearest block
        uint256[] memory checkPointBlockNumbers = epochCheckPointBlockNumbers[epoch];
        uint256 nearest = 0;
        for (uint256 i = 0; i < checkPointBlockNumbers.length; i++) {
            uint256 checkPointBlockNumber = checkPointBlockNumbers[i];
            if (
                checkPointBlockNumber > blockNumber &&
                checkPointBlockNumber < nearest
            ) {
                nearest = checkPointBlockNumber;
            }
        }
        checkPointBlock = checkPointBlocks[nearest];
    }

    //Function accepts parameters epoch (uint256) and mmrRoot(uint256) the function is public and returns a boolean
    //the boolean is found in the epochMmrRoots array two levels deep
    function isValidCheckPoint(uint256 epoch, bytes32 mmrRoot) public view returns (bool status) {
        return epochMmrRoots[epoch][mmrRoot];
    }
}