// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "hardhat/console.sol";

import {ISettlement} from "contracts/interfaces/ISettlement.sol";
import {IERC20CodecV1} from "contracts/interfaces/IERC20CodecV1.sol";
import {IERC20Mint} from "contracts/interfaces/IERC20Mint.sol";
import {IERC20Burn} from "contracts/interfaces/IERC20Burn.sol";
import {ISettlementHandler} from "contracts/interfaces/ISettlementHandler.sol";
import {AddressCast} from "contracts/libraries/AddressCast.sol";
import {Message, PayloadType, CrossChainMsgStatus} from "contracts/libraries/Message.sol";
import {MessageV1Codec} from "contracts/libraries/MessageV1Codec.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {BaseSettlementHandler} from "contracts/BaseSettlementHandler.sol";
import "contracts/libraries/ERC20Payload.sol";

contract ChakraSettlementHandler is BaseSettlementHandler, ISettlementHandler {
    mapping(string => mapping(uint256 => bool)) public handler_whitelist;

    /**
     * @dev The address of the codec contract
     */
    IERC20CodecV1 public codec;

    // Enum to represent transaction status
    enum TxStatus {
        Unknow,
        Pending,
        Minted,
        Burned,
        Failed
    }

    /**
     * @dev Checks if a handler is valid for a given chain
     * @param chain_name The name of the chain
     * @param handler The handler address
     * @return bool True if the handler is valid, false otherwise
     */
    function is_valid_handler(
        string memory chain_name,
        uint256 handler
    ) public view returns (bool) {
        return handler_whitelist[chain_name][handler];
    }

    /**
     * @dev Adds a handler to the whitelist for a given chain
     * @param chain_name The name of the chain
     * @param handler The handler address to add
     */
    function add_handler(
        string memory chain_name,
        uint256 handler
    ) external onlyOwner {
        handler_whitelist[chain_name][handler] = true;
    }

    /**
     * @dev Removes a handler from the whitelist for a given chain
     * @param chain_name The name of the chain
     * @param handler The handler address to remove
     */
//q. frontrunnning this calls?
    function remove_handler(
        string memory chain_name,
        uint256 handler
    ) external onlyOwner {
        handler_whitelist[chain_name][handler] = false;
    }

    /**
     * @dev Initializes the contract
     * @param _owner The owner address
     * @param _mode mode The settlement mode
     * @param _chain The chain name
     * @param _token The token address
     * @param _codec The codec address
     * @param _verifier The verifier address
     * @param _settlement The settlement address
     */
    function initialize(
        address _owner,
        SettlementMode _mode,
        string memory _chain,
        address _token,
        address _codec,
        address _verifier,
        address _settlement
    ) public initializer {
        // Initialize the base settlement handler
        _Settlement_handler_init(
            _owner,
            _mode,
            _token,
            _verifier,
            _chain,
            _settlement
        );
        codec = IERC20CodecV1(_codec);
    }

    /**
     * @dev Initiates a cross-chain ERC20 settlement
     * @param to_chain The destination chain
     * @param to_handler The destination handler
     * @param to_token The destination token
     * @param to The recipient address
     * @param amount The amount to transfer
     */
//to is the address of the recipient here denoted via uint256
    function cross_chain_erc20_settlement(
        string memory to_chain,
        uint256 to_handler,
        uint256 to_token,
        uint256 to,
        uint256 amount
    ) external {
        require(amount > 0, "Amount must be greater than 0");
        require(to != 0, "Invalid to address");
        require(to_handler != 0, "Invalid to handler address");
        require(to_token != 0, "Invalid to token address");

//@audit- why does it erc20_lock for all first mode MINTBURN should instead call _erc20_burn() right?
        if (mode == SettlementMode.MintBurn) {
            _erc20_lock(msg.sender, address(this), amount);
        } else if (mode == SettlementMode.LockUnlock) {
            _erc20_lock(msg.sender, address(this), amount);
        } else if (mode == SettlementMode.LockMint) {
            _erc20_lock(msg.sender, address(this), amount);
        } else if (mode == SettlementMode.BurnUnlock) {
            _erc20_burn(msg.sender, amount);
        }

        {
            // Increment nonce for the sender
//i- nonce is incremented for caller, once in handler contract and then in settlement contract via settlement.send_cross_chain_msg(
            //     to_chain,
            //     msg.sender,
            //     to_handler,
            //     PayloadType.ERC20,
            //     cross_chain_msg_bytes
            // );
            nonce_manager[msg.sender] += 1;
        }

        // Create a new cross chain tx
        uint256 txid = uint256(
            keccak256(
                abi.encodePacked(
                    chain,
                    to_chain,
                    msg.sender, // from address for settlement to calculate txid
                    address(this), //  from handler for settlement to calculate txid
                    to_handler,
                    nonce_manager[msg.sender]
                )
            )
        );

        {
            // Save the cross chain tx
            create_cross_txs[txid] = CreatedCrossChainTx(
                txid,
                chain,
                to_chain,
                msg.sender,
                to,
                address(this),
                to_token,
                amount,
                CrossChainTxStatus.Pending
            );
        }

        {
            // Create a new cross chain msg id
            cross_chain_msg_id_counter += 1;
            uint256 cross_chain_msg_id = uint256(
                keccak256(
                    abi.encodePacked(
                        cross_chain_msg_id_counter,
                        address(this),
                        msg.sender,
                        nonce_manager[msg.sender]
                    )
                )
            );
            // Create a erc20 transfer payload
struct ERC20TransferPayload {
    ERC20Method method_id; // The method identifier (should be Transfer for this struct)
    uint256 from; // The address sending the tokens (as a uint256)
    uint256 to; // The address receiving the tokens (as a uint256)
    uint256 from_token; // The token address on the source chain (as a uint256)
    uint256 to_token; // The token address on the destination chain (as a uint256)
    uint256 amount; // The amount of tokens to transfer
}
            ERC20TransferPayload memory payload = ERC20TransferPayload(
                ERC20Method.Transfer,
                AddressCast.to_uint256(msg.sender),
                to,
                AddressCast.to_uint256(token),
                to_token,
                amount
            );

            // Create a cross chain msg
            Message memory cross_chain_msg = Message(
                cross_chain_msg_id,
                PayloadType.ERC20,
                codec.encode_transfer(payload)
            );

            // Encode the cross chain msg
            bytes memory cross_chain_msg_bytes = MessageV1Codec.encode(
                cross_chain_msg
            );

            // Send the cross chain msg
// the below call is made to a public fn of contract
            settlement.send_cross_chain_msg(
                to_chain,
                msg.sender,
                to_handler,
                PayloadType.ERC20,
                cross_chain_msg_bytes
            );
        }

        emit CrossChainLocked(
            txid,
            msg.sender,
            to,
            chain,
            to_chain,
            address(this),
            to_token,
            amount,
            mode
        );
    }

    function _erc20_mint(address account, uint256 amount) internal {
        IERC20Mint(token).mint_to(account, amount);
    }

    function _erc20_burn(address account, uint256 amount) internal {
        require(
            IERC20(token).balanceOf(account) >= amount,
            "Insufficient balance"
        );

        IERC20Burn(token).burn_from(account, amount);
    }

    /**
     * @dev Lock erc20 token
     * @param from The lock token from account
     * @param to The locked token to account
//qa- improper natspec below line *lock
     * @param amount The amount to unlock
     */
    function _erc20_lock(address from, address to, uint256 amount) internal {
        _safe_transfer_from(from, to, amount);
    }

    /**
     * @dev Unlock erc20 token
     * @param to The token unlocked to account
     * @param amount The amount to unlock
     */
    function _erc20_unlock(address to, uint256 amount) internal {
        _safe_transfer(to, amount);
    }

    function _safe_transfer_from(
        address from,
        address to,
        uint256 amount
    ) internal {
        require(
            IERC20(token).balanceOf(from) >= amount,
            "Insufficient balance"
        );

        // transfer tokens
//q.  does some tokens silently fail if the allowance is not enough (not reverting)
        IERC20(token).transferFrom(from, to, amount);
    }

    function _safe_transfer(address to, uint256 amount) internal {
        require(
            IERC20(token).balanceOf(address(this)) >= amount,
            "Insufficient balance"
        );

        // transfer tokens
//q. - fails for some tokens due to no return value check (already in 4naLyzer report).
        IERC20(token).transfer(to, amount);
    }

    /**
     * @dev Checks if the payload type is valid
     * @param payload_type The payload type to check
     * @return bool True if valid, false otherwise
     */
    function isValidPayloadType(
        PayloadType payload_type
    ) internal pure returns (bool) {
        return (payload_type == PayloadType.ERC20);
    }

// OK
//q. ERC-777 tokens allows reentrancy via hook.. use nonReentrant modifier
    /**
     * @dev Receives a cross-chain message
     * @param from_chain The source chain
     * @param from_handler The source handler
     * @param payload_type The type of payload
     * @param payload The payload data
     * @return bool True if successful, false otherwise
     */
    function receive_cross_chain_msg(
        uint256 /**txid */,
        string memory from_chain,
        uint256 /**from_address */,
        uint256 from_handler,
        PayloadType payload_type,
        bytes calldata payload,
        uint8 /**sign type */,
        bytes calldata /**signaturs */
    ) external onlySettlement returns (bool) {
        //  from_handler need in whitelist
        if (is_valid_handler(from_chain, from_handler) == false) {
            return false;
        }
        bytes calldata msg_payload = MessageV1Codec.payload(payload);

        require(isValidPayloadType(payload_type), "Invalid payload type");

        if (payload_type == PayloadType.ERC20) {
            // Cross chain transfer
            {
receiver chain either mints or unlocks
lly, source chain either burns or locks
                // Decode transfer payload
                ERC20TransferPayload memory transfer_payload = codec
                    .deocde_transfer(msg_payload);

                if (mode == SettlementMode.MintBurn) {
                    _erc20_mint(
                        AddressCast.to_address(transfer_payload.to),
                        transfer_payload.amount
                    );
                    return true;
                } else if (mode == SettlementMode.LockUnlock) {
                    _erc20_unlock(
                        AddressCast.to_address(transfer_payload.to),
                        transfer_payload.amount
                    );

                    return true;
                } else if (mode == SettlementMode.LockMint) {
                    _erc20_mint(
                        AddressCast.to_address(transfer_payload.to),
                        transfer_payload.amount
                    );
                    return true;
                } else if (mode == SettlementMode.BurnUnlock) {
                    _erc20_unlock(
                        AddressCast.to_address(transfer_payload.to),
                        transfer_payload.amount
                    );
                    return true;
                }
            }
        }

        return false;
    }

//i- called only by the settlement contract.
    /**
     * @dev Receives a cross-chain callback
     * @param txid The transaction ID
     * @param from_chain The source chain
     * @param from_handler The source handler
     * @param status The status of the cross-chain message
     * @return bool True if successful, false otherwise
     */
// based on the returning value from this callback(), 
Also In the settlement contract it will either mark the `cross_chain_tx[txid]` status as Failed or Settled.
    function receive_cross_chain_callback(
        uint256 txid,
        string memory from_chain,
        uint256 from_handler,
        CrossChainMsgStatus status,
        uint8 /* sign_type */, // validators signature type /  multisig or bls sr25519
        bytes calldata /* signatures */
    ) external onlySettlement returns (bool) {
        //  from_handler need in whitelist
        if (is_valid_handler(from_chain, from_handler) == false) {
            return false;
        }

        require(
            create_cross_txs[txid].status == CrossChainTxStatus.Pending,
            "invalid CrossChainTxStatus"
        );

        if (status == CrossChainMsgStatus.Success) {
            if (mode == SettlementMode.MintBurn) {
// q. why is it burning in receive callback() shouldn't it be minting instead??
                _erc20_burn(address(this), create_cross_txs[txid].amount);
            }

            create_cross_txs[txid].status = CrossChainTxStatus.Settled;
        }

        if (status == CrossChainMsgStatus.Failed) {


/ updates the status state in this handler contract. 
/ if it fails here on handler side, then on settlement side also the status is = Failed (as settlement contract calls this fn to get the status on handler to updates it's own status)


            create_cross_txs[txid].status = CrossChainTxStatus.Failed;
        }

        return true;
    }
}
//OK
/ Task- Please write the flow of functions and state changes from one fn to another (focussing on external fns for user actions)