// SPDX-License-Identifier: UNLICENSED
//Articulate programming language and version
pragma solidity 0.7.3;

//Encoder for hashing algorithms
pragma experimental ABIEncoderV2;

//importing all the dependencies 
import "./HarmonyLightClient.sol";
import "./lib/MMRVerifier.sol";
import "./HarmonyProver.sol";
import "./TokenLocker.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

//The contract inherits all of the content in the smart contracts imported from TokenLocker.sol and OwnableUpgradeable.sol
contract TokenLockerOnEthereum is TokenLocker, OwnableUpgradeable {

    //defining HarmonyLightClient object as a public variable lightclient
    HarmonyLightClient public lightclient;

    //mapping bytes to bool for public var spentReceipt
    mapping(bytes32 => bool) public spentReceipt;

    //define function intialize which inherits the private function __Ownable_init(); from dependency
    function initialize() external initializer {
        __Ownable_init();
    }

    //function changes the light client, it accepts a EthereumLightCleint type newClient parameter
    function changeLightClient(HarmonyLightClient newClient)
        external
        onlyOwner
    {
        lightclient = newClient;
    }

    //function bind accepts address otherSide parameter at which becomes avaiable to onlyOwner
    //sets the otherSideBridge to the otherSide parameter passed in
    function bind(address otherSide) external onlyOwner {
        otherSideBridge = otherSide;
    }

    //The function uses the Harmony Parser block header to define a SC memory variable header
    //Then mmrProof and recepient tree from the merkleproof
    function validateAndExecuteProof(
        HarmonyParser.BlockHeader memory header,
        MMRVerifier.MMRProof memory mmrProof,
        MPT.MerkleProof memory receiptdata
    ) external {
    //It's required that the header.epoch mmrProof.root is a valid checkpoint otherwise the checkpoint validation failed
        require(lightclient.isValidCheckPoint(header.epoch, mmrProof.root), "checkpoint validation failed");

        //the block hash is set to the output of getBlockHash function from HarmonyParser passing in the header
        bytes32 blockHash = HarmonyParser.getBlockHash(header);

        //the rootHash is assigned to the receipts root of the header object
        bytes32 rootHash = header.receiptsRoot;

        //a tuple with the status boolean and the message (string) is assigned to the output of the HarmonyProver that verifies
        //the header by acepting the header and proof
        (bool status, string memory message) = HarmonyProver.verifyHeader(
            header,
            mmrProof
        );

        //set the recepient hash to the output of the hashing algorithm
        //since we imported pragma experimental ABIEncoderV2 into the file 
        //into it we pass the abi encode packed (blockHash,rootHash,receiptdata.key)
        require(status, "block header could not be verified");
        bytes32 receiptHash = keccak256(
            abi.encodePacked(blockHash, rootHash, receiptdata.key)
        );
        //we require that the spentReceipt of the receiptHash returns false otherwise this means double spending!
        require(spentReceipt[receiptHash] == false, "double spent!");
        //tuple status,mesage set to the HarmonyProver reciept verification funciton 
        (status, message) = HarmonyProver.verifyReceipt(header, receiptdata);
        require(status, "receipt data could not be verified");
        spentReceipt[receiptHash] = true;
        uint256 executedEvents = execute(receiptdata.expectedValue);
        require(executedEvents > 0, "no valid event");
    }
}
