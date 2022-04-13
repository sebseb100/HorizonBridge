// SPDX-License-Identifier: UNLICENSED
//Define program language
pragma solidity 0.7.3;
pragma experimental ABIEncoderV2;

//Import dependencies 
import "@openzeppelin/contracts-upgradeable/math/SafeMathUpgradeable.sol";
import "./EthereumLightClient.sol";
import "./EthereumProver.sol";
import "./TokenLocker.sol";

//Define TokenLocker smart contract and inherit the smart contracts contents
contract TokenLockerOnHarmony is TokenLocker, OwnableUpgradeable {

    //tools
    using RLPReader for RLPReader.RLPItem;
    using RLPReader for bytes;
    using SafeMathUpgradeable for uint256;
    using SafeERC20Upgradeable for IERC20Upgradeable;

    //EthereumLightClientt as public object lightclient 
    EthereumLightClient public lightclient;

    mapping(bytes32 => bool) public spentReceipt;

    //define function intialize which inherits the private function __Ownable_init(); from dependency
    function initialize() external initializer {
        __Ownable_init();
    }

    //function changes the light client, it accepts a EthereumLightCleint type newClient parameter
    function changeLightClient(EthereumLightClient newClient)
        external
        onlyOwner
    {
        //Assigns the lightcleint value to newClient
        lightclient = newClient;
    }
    //function bind accepts address otherSide parameter at which becomes avaiable to onlyOwner
    //sets the otherSideBridge to the otherSide parameter passed in
    function bind(address otherSide) external onlyOwner {
        otherSideBridge = otherSide;
    }

    //The funciton variables include the block number, root hash, the mapped key, and the proof
    function validateAndExecuteProof(
        uint256 blockNo,
        bytes32 rootHash,
        bytes calldata mptkey,
        bytes calldata proof
    ) external {
        //the blockHash is set to the lightcleint.blocksByHeight(blockNo, 0) 
        bytes32 blockHash = bytes32(lightclient.blocksByHeight(blockNo, 0));

        //require that when the VerifyReceiptsHash the blockHash matches the rootHash
        //otherwise it's the wrong receipt hash
        require(
            lightclient.VerifyReceiptsHash(blockHash, rootHash),
            "wrong receipt hash"
        );
        //receiptHash of type bytes 32 is set to the value returned by the hashing functions by passing in encode packed
        //block hash, root hash, and mapped key 
        bytes32 receiptHash = keccak256(
            abi.encodePacked(blockHash, rootHash, mptkey)
        );

        //require that in the spentReceipt array the position of the receiptHash alligns with false other wise it's double spent
        require(spentReceipt[receiptHash] == false, "double spent!");
        bytes memory rlpdata = EthereumProver.validateMPTProof(
            rootHash,
            mptkey,
            proof
        );
        spentReceipt[receiptHash] = true;
        uint256 executedEvents = execute(rlpdata);
        require(executedEvents > 0, "no valid event");
    }
}
