/*
 * Copyright (C) 2018 The ontology Authors
 * This file is part of The ontology library.
 *
 * The ontology is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ontology is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with The ontology.  If not, see <http://www.gnu.org/licenses/>.
 */

package config

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/common/constants"
	"github.com/ontio/ontology/common/log"
	"github.com/ontio/ontology/common/serialization"
	"github.com/ontio/ontology/errors"
)

var Version = "" //Set value when build project

const (
	DEFAULT_CONFIG_FILE_NAME = "./config.json"
	DEFAULT_WALLET_FILE_NAME = "./wallet.dat"
	MIN_GEN_BLOCK_TIME       = 2
	DEFAULT_GEN_BLOCK_TIME   = 6
	DBFT_MIN_NODE_NUM        = 4 //min node number of dbft consensus
	SOLO_MIN_NODE_NUM        = 1 //min node number of solo consensus
	VBFT_MIN_NODE_NUM        = 4 //min node number of vbft consensus

	CONSENSUS_TYPE_DBFT = "dbft"
	CONSENSUS_TYPE_SOLO = "solo"
	CONSENSUS_TYPE_VBFT = "vbft"

	DEFAULT_LOG_LEVEL                       = log.InfoLog
	DEFAULT_MAX_LOG_SIZE                    = 100 //MByte
	DEFAULT_NODE_PORT                       = uint(20338)
	DEFAULT_CONSENSUS_PORT                  = uint(20339)
	DEFAULT_RPC_PORT                        = uint(20336)
	DEFAULT_RPC_LOCAL_PORT                  = uint(20337)
	DEFAULT_REST_PORT                       = uint(20334)
	DEFAULT_WS_PORT                         = uint(20335)
	DEFAULT_MAX_CONN_IN_BOUND               = uint(1024)
	DEFAULT_MAX_CONN_OUT_BOUND              = uint(1024)
	DEFAULT_MAX_CONN_IN_BOUND_FOR_SINGLE_IP = uint(16)
	DEFAULT_HTTP_INFO_PORT                  = uint(0)
	DEFAULT_MAX_TX_IN_BLOCK                 = 60000
	DEFAULT_MAX_SYNC_HEADER                 = 500
	DEFAULT_ENABLE_CONSENSUS                = true
	DEFAULT_ENABLE_EVENT_LOG                = true
	DEFAULT_CLI_RPC_PORT                    = uint(20000)
	DEFUALT_CLI_RPC_ADDRESS                 = "127.0.0.1"
	DEFAULT_GAS_LIMIT                       = 20000
	DEFAULT_GAS_PRICE                       = 500

	DEFAULT_DATA_DIR      = "./Chain"
	DEFAULT_RESERVED_FILE = "./peers.rsv"
)

const (
	NETWORK_ID_MAIN_NET      = 1
	NETWORK_ID_POLARIS_NET   = 2
	NETWORK_ID_SOLO_NET      = 3
	NETWORK_NAME_MAIN_NET    = "ontology"
	NETWORK_NAME_POLARIS_NET = "polaris"
	NETWORK_NAME_SOLO_NET    = "testmode"
)

var NETWORK_MAGIC = map[uint32]uint32{
	NETWORK_ID_MAIN_NET:    constants.NETWORK_MAGIC_MAINNET, //Network main
	NETWORK_ID_POLARIS_NET: constants.NETWORK_MAGIC_POLARIS, //Network polaris
	NETWORK_ID_SOLO_NET:    0,                               //Network solo
}

var NETWORK_NAME = map[uint32]string{
	NETWORK_ID_MAIN_NET:    NETWORK_NAME_MAIN_NET,
	NETWORK_ID_POLARIS_NET: NETWORK_NAME_POLARIS_NET,
	NETWORK_ID_SOLO_NET:    NETWORK_NAME_SOLO_NET,
}

func GetNetworkMagic(id uint32) uint32 {
	nid, ok := NETWORK_MAGIC[id]
	if ok {
		return nid
	}
	return id
}

func GetNetworkName(id uint32) string {
	name, ok := NETWORK_NAME[id]
	if ok {
		return name
	}
	return fmt.Sprintf("%d", id)
}

var PolarisConfig = &GenesisConfig{
	// SeedList: []string{
	// 	"polaris1.ont.io:20338",
	// 	"polaris2.ont.io:20338",
	// 	"polaris3.ont.io:20338",
	// 	"polaris4.ont.io:20338"},
	SeedList: []string{
		"127.0.0.1:20418",
		"127.0.0.1:20428",
		"127.0.0.1:20438",
		"127.0.0.1:20448"},
	ConsensusType: CONSENSUS_TYPE_VBFT,
	VBFT: &VBFTConfig{
		N:                    7,
		C:                    2,
		K:                    7,
		L:                    112,
		BlockMsgDelay:        10000,
		HashMsgDelay:         10000,
		PeerHandshakeTimeout: 10,
		MaxBlockChangeView:   3000,
		AdminOntID:           "did:ont:AMAx993nE6NEqZjwBssUfopxnnvTdob9ij",
		MinInitStake:         10000,
		VrfValue:             "1c9810aa9822e511d5804a9c4db9dd08497c31087b0daafa34d768a3253441fa20515e2f30f81741102af0ca3cefc4818fef16adb825fbaa8cad78647f3afb590e",
		VrfProof:             "c57741f934042cb8d8b087b44b161db56fc3ffd4ffb675d36cd09f83935be853d8729f3f5298d12d6fd28d45dde515a4b9d7f67682d182ba5118abf451ff1988",
		Peers: []*VBFTPeerStakeInfo{
			{
				Index:      1,
				PeerPubkey: "037c9e6c6a446b6b296f89b722cbf686b81e0a122444ef05f0f87096777663284b",
				Address:    "AXmQDzzvpEtPkNwBEFsREzApTTDZFW6frD",
				InitPos:    10000,
			},
			{
				Index:      2,
				PeerPubkey: "03dff4c63267ae5e23da44ace1bc47d0da1eb8d36fd71181dcccf0e872cb7b31fa",
				Address:    "AY5W6p4jHeZG2jjW6nS1p4KDUhcqLkU6jz",
				InitPos:    20000,
			},
			{
				Index:      3,
				PeerPubkey: "0205bc592aa9121428c4144fcd669ece1fa73fee440616c75624967f83fb881050",
				Address:    "ALZVrZrFqoSvqyi38n7mpPoeDp7DMtZ9b6",
				InitPos:    30000,
			},
			{
				Index:      4,
				PeerPubkey: "030a34dcb075d144df1f65757b85acaf053395bb47b019970607d2d1cdd222525c",
				Address:    "AMogjmLf2QohTcGST7niV75ekZfj44SKme",
				InitPos:    40000,
			},
			{
				Index:      5,
				PeerPubkey: "021844159f97d81da71da52f84e8451ee573c83b296ff2446387b292e44fba5c98",
				Address:    "AZzQTkZvjy7ih9gjvwU8KYiZZyNoy6jE9p",
				InitPos:    30000,
			},
			{
				Index:      6,
				PeerPubkey: "020cc76feb375d6ea8ec9ff653bab18b6bbc815610cecc76e702b43d356f885835",
				Address:    "AKEqQKmxCsjWJz8LPGryXzb6nN5fkK1WDY",
				InitPos:    20000,
			},
			{
				Index:      7,
				PeerPubkey: "03aa4d52b200fd91ca12deff46505c4608a0f66d28d9ae68a342c8a8c1266de0f9",
				Address:    "AQNpGWz4oHHFBejtBbakeR43DHfen7cm8L",
				InitPos:    10000,
			},
		},
	},
	DBFT: &DBFTConfig{},
	SOLO: &SOLOConfig{},
}

var MainNetConfig = &GenesisConfig{
	// SeedList: []string{
	// 	"seed1.ont.io:20338",
	// 	"seed2.ont.io:20338",
	// 	"seed3.ont.io:20338",
	// 	"seed4.ont.io:20338",
	// 	"seed5.ont.io:20338"},
	SeedList: []string{
		"127.0.0.1:20418",
		"127.0.0.1:20428",
		"127.0.0.1:20438",
		"127.0.0.1:20448",
		"127.0.0.1:20458",
		"127.0.0.1:20468",
		"127.0.0.1:20478"},
	ConsensusType: CONSENSUS_TYPE_VBFT,
	VBFT: &VBFTConfig{
		N:                    7,
		C:                    2,
		K:                    7,
		L:                    112,
		BlockMsgDelay:        10000,
		HashMsgDelay:         10000,
		PeerHandshakeTimeout: 10,
		MaxBlockChangeView:   120000,
		AdminOntID:           "did:ont:AdjfcJgwru2FD8kotCPvLDXYzRjqFjc9Tb",
		MinInitStake:         100000,
		VrfValue:             "1c9810aa9822e511d5804a9c4db9dd08497c31087b0daafa34d768a3253441fa20515e2f30f81741102af0ca3cefc4818fef16adb825fbaa8cad78647f3afb590e",
		VrfProof:             "c57741f934042cb8d8b087b44b161db56fc3ffd4ffb675d36cd09f83935be853d8729f3f5298d12d6fd28d45dde515a4b9d7f67682d182ba5118abf451ff1988",
		Peers: []*VBFTPeerStakeInfo{
			{
				Index:      1,
				PeerPubkey: "ffff89c6d35521e0255d47f0097e202431b1923047622eae4a0a723bd755e37b8fce79a90f3263dfbfc29babf5427a34f0ba42085275ed78073b074a99a1bacc4e2a177b62a42b3afb627b4ad22d9843ab0cf57cb5461ebc780aa3d623dbe061b32a285fa1bbe99121ec8ec8cb1f135d7ff50d760cf8e14d791f0cd93a125c4b3112",
				Address:    "Ad3r9vpt7aVC6zcrBXvNwuReTkenrigKCr",
			},
			{
				Index:      2,
				PeerPubkey: "ffff401d0ebd1c0ae6dd013ac04215c4c0c0a7a21d7f0401b6809137f5475b1ec2f00d02a0b293edf29795c2ffaeee8cbe6c7de121a70c3ba44a12f5e5250413b1ed57af102cbb876a715f38830116954d39d63b760aed6657b4d2f3d6c83198cecc1a7ed0c48b83faf6c697e01675755921620561a026186de9ffb98b469f028599",
				Address:    "AKkW4FjMMDt8waDZ7Y3KLYoSSvai1i6gUC",
			},
			{
				Index:      3,
				PeerPubkey: "ffff2e2da6d8f0da61badbdb66567b0b4fb5b09e8ed924216d58a886f189aa1bc8d458b97f030c8d872dc1210b93083d0220a83e8383a0be7308a389832518d0c76885a398e3e40a00f5ea41283e5f909350345733847b6ec06847e46e2eadb2e5ef4fd4aca6408f1153ffbc73fa5a14236cb9764463bfd1c4ce56b676257bc1c9e0",
				Address:    "AVygXFE4Szt2fWAgfjFPn1kNhphCTKQ9rW",
			},
			{
				Index:      4,
				PeerPubkey: "ffff4e76b2f0846422f27a0c905615129e6609646587cc03d641561142d29e9272f03f22bc90deb1a3e7bd0636c806fc4fc576e4528d721782fc76dc2854891c8c04453a5e497fa29b22ac65564ca6626fb5835795ff4419f3d09eb3e7ede7395f1d6d6980fe6e46c2b598e834ea37057777a58989c60b0b170a4bd54a18aeab699c",
				Address:    "AeR1zfA1v1TYb7apqzjzWZ6Xv4xXR3tdDU",
			},
			{
				Index:      5,
				PeerPubkey: "ffff2f8fddf1571da8b6151b92f58a2b6a7d27cdb7cd81bba10611e1c34aff089190359ca5285613b11c64aeb66213a3a503a7ee18c846dcba8ecefcc71218122f516f8e59b36c0185c39aa9beceb3f432057b6baf428cd24283d250c1e44057597b8cec001a23536012001eb7f7b686b416b507da2e9515acb5d34c52d82aee9fcd",
				Address:    "Ae2dp3H2kY6vcMcQBfhc5DUQVCS7Yfuw3B",
			},
			{
				Index:      6,
				PeerPubkey: "ffff7c2196db99fa816767ee84e129544d9d4c2e9353ee4b3298934fd907270c6c421cb3b88d203b7d101b8e706d605a7f96adfec33c104ca6499d51d95ec00ace7a220ab2ca679e3fe3f9a64e024293e38c08c9ac1841dd0e5809794a9205e4ad7f2beb07df3198031d913b17c83e76b63ef1246f0a3577f7d69fee87445c184dc5",
				Address:    "ALqNJ9HVRxxgbKMqfaMThcrYi3GLWn6qFw",
			},
			{
				Index:      7,
				PeerPubkey: "ffff0b4fd948d1038ce678d9ca07e410029a52a29ff8c8b378e6229c694439a56f2d2ab18043ec96732816b7fbd00bac84cd9823353b8df55291937e96738b80ae838abee92f49439dc7bcb437954145587186e90c9f991c67eb770f0709236b0f666b71d3fb4d1c687c380f5575c5dd34b5849e68645bdef82c3402ff30283caf26",
				Address:    "AbtsQ3NGXm1SHtLNo9YL2gTveje6tMcUwE",
			},
		},
	},
	DBFT: &DBFTConfig{},
	SOLO: &SOLOConfig{},
}

var DefConfig = NewOntologyConfig()

type GenesisConfig struct {
	SeedList      []string
	ConsensusType string
	VBFT          *VBFTConfig
	DBFT          *DBFTConfig
	SOLO          *SOLOConfig
}

func NewGenesisConfig() *GenesisConfig {
	return &GenesisConfig{
		SeedList:      make([]string, 0),
		ConsensusType: CONSENSUS_TYPE_DBFT,
		VBFT:          &VBFTConfig{},
		DBFT:          &DBFTConfig{},
		SOLO:          &SOLOConfig{},
	}
}

//
// VBFT genesis config, from local config file
//
type VBFTConfig struct {
	N                    uint32               `json:"n"` // network size
	C                    uint32               `json:"c"` // consensus quorum
	K                    uint32               `json:"k"`
	L                    uint32               `json:"l"`
	BlockMsgDelay        uint32               `json:"block_msg_delay"`
	HashMsgDelay         uint32               `json:"hash_msg_delay"`
	PeerHandshakeTimeout uint32               `json:"peer_handshake_timeout"`
	MaxBlockChangeView   uint32               `json:"max_block_change_view"`
	MinInitStake         uint32               `json:"min_init_stake"`
	AdminOntID           string               `json:"admin_ont_id"`
	VrfValue             string               `json:"vrf_value"`
	VrfProof             string               `json:"vrf_proof"`
	Peers                []*VBFTPeerStakeInfo `json:"peers"`
}

func (this *VBFTConfig) Serialize(w io.Writer) error {
	if err := serialization.WriteUint32(w, this.N); err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.WriteUint32, serialize n error!")
	}
	if err := serialization.WriteUint32(w, this.C); err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.WriteUint32, serialize c error!")
	}
	if err := serialization.WriteUint32(w, this.K); err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.WriteUint32, serialize k error!")
	}
	if err := serialization.WriteUint32(w, this.L); err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.WriteUint32, serialize l error!")
	}
	if err := serialization.WriteUint32(w, this.BlockMsgDelay); err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.WriteUint32, serialize block_msg_delay error!")
	}
	if err := serialization.WriteUint32(w, this.HashMsgDelay); err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.WriteUint32, serialize hash_msg_delay error!")
	}
	if err := serialization.WriteUint32(w, this.PeerHandshakeTimeout); err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.WriteUint32, serialize peer_handshake_timeout error!")
	}
	if err := serialization.WriteUint32(w, this.MaxBlockChangeView); err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.WriteUint32, serialize max_block_change_view error!")
	}
	if err := serialization.WriteUint32(w, this.MinInitStake); err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.WriteUint32, serialize min_init_stake error!")
	}
	if err := serialization.WriteString(w, this.AdminOntID); err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.WriteString, serialize admin_ont_id error!")
	}
	if err := serialization.WriteString(w, this.VrfValue); err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.WriteString, serialize vrf_value error!")
	}
	if err := serialization.WriteString(w, this.VrfProof); err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.WriteString, serialize vrf_proof error!")
	}
	if err := serialization.WriteVarUint(w, uint64(len(this.Peers))); err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.WriteVarUint, serialize peer length error!")
	}
	for _, peer := range this.Peers {
		if err := peer.Serialize(w); err != nil {
			return errors.NewDetailErr(err, errors.ErrNoCode, "serialize peer error!")
		}
	}
	return nil
}

func (this *VBFTConfig) Deserialize(r io.Reader) error {
	n, err := serialization.ReadUint32(r)
	if err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.ReadUint32, deserialize n error!")
	}
	c, err := serialization.ReadUint32(r)
	if err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.ReadUint32, deserialize c error!")
	}
	k, err := serialization.ReadUint32(r)
	if err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.ReadUint32, deserialize k error!")
	}
	l, err := serialization.ReadUint32(r)
	if err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.ReadUint32, deserialize l error!")
	}
	blockMsgDelay, err := serialization.ReadUint32(r)
	if err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.ReadUint32, deserialize blockMsgDelay error!")
	}
	hashMsgDelay, err := serialization.ReadUint32(r)
	if err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.ReadUint32, deserialize hashMsgDelay error!")
	}
	peerHandshakeTimeout, err := serialization.ReadUint32(r)
	if err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.ReadUint32, deserialize peerHandshakeTimeout error!")
	}
	maxBlockChangeView, err := serialization.ReadUint32(r)
	if err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.ReadUint32, deserialize maxBlockChangeView error!")
	}
	minInitStake, err := serialization.ReadUint32(r)
	if err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.ReadUint32, deserialize minInitStake error!")
	}
	adminOntID, err := serialization.ReadString(r)
	if err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.ReadString, deserialize adminOntID error!")
	}
	vrfValue, err := serialization.ReadString(r)
	if err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.ReadString, deserialize vrfValue error!")
	}
	vrfProof, err := serialization.ReadString(r)
	if err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.ReadString, deserialize vrfProof error!")
	}
	length, err := serialization.ReadVarUint(r, 0)
	if err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.ReadVarUint, deserialize peer length error!")
	}
	peers := make([]*VBFTPeerStakeInfo, 0)
	for i := 0; uint64(i) < length; i++ {
		peer := new(VBFTPeerStakeInfo)
		err = peer.Deserialize(r)
		if err != nil {
			return errors.NewDetailErr(err, errors.ErrNoCode, "deserialize peer error!")
		}
		peers = append(peers, peer)
	}
	this.N = n
	this.C = c
	this.K = k
	this.L = l
	this.BlockMsgDelay = blockMsgDelay
	this.HashMsgDelay = hashMsgDelay
	this.PeerHandshakeTimeout = peerHandshakeTimeout
	this.MaxBlockChangeView = maxBlockChangeView
	this.MinInitStake = minInitStake
	this.AdminOntID = adminOntID
	this.VrfValue = vrfValue
	this.VrfProof = vrfProof
	this.Peers = peers
	return nil
}

type VBFTPeerStakeInfo struct {
	Index      uint32 `json:"index"`
	PeerPubkey string `json:"peerPubkey"`
	Address    string `json:"address"`
	InitPos    uint64 `json:"initPos"`
}

func (this *VBFTPeerStakeInfo) Serialize(w io.Writer) error {
	if err := serialization.WriteUint32(w, this.Index); err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.WriteUint32, serialize index error!")
	}
	if err := serialization.WriteString(w, this.PeerPubkey); err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.WriteUint32, serialize peerPubkey error!")
	}
	address, err := common.AddressFromBase58(this.Address)
	if err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "common.AddressFromBase58, address format error!")
	}
	if err := address.Serialize(w); err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.WriteUint32, serialize address error!")
	}
	if err := serialization.WriteUint64(w, this.InitPos); err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.WriteUint32, serialize initPos error!")
	}
	return nil
}

func (this *VBFTPeerStakeInfo) Deserialize(r io.Reader) error {
	index, err := serialization.ReadUint32(r)
	if err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.ReadUint32, deserialize index error!")
	}
	peerPubkey, err := serialization.ReadString(r)
	if err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.ReadUint32, deserialize peerPubkey error!")
	}
	address := new(common.Address)
	err = address.Deserialize(r)
	if err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "address.Deserialize, deserialize address error!")
	}
	initPos, err := serialization.ReadUint64(r)
	if err != nil {
		return errors.NewDetailErr(err, errors.ErrNoCode, "serialization.ReadUint32, deserialize initPos error!")
	}
	this.Index = index
	this.PeerPubkey = peerPubkey
	this.Address = address.ToBase58()
	this.InitPos = initPos
	return nil
}

type DBFTConfig struct {
	GenBlockTime uint
	Bookkeepers  []string
}

type SOLOConfig struct {
	GenBlockTime uint
	Bookkeepers  []string
}

type CommonConfig struct {
	LogLevel       uint
	NodeType       string
	EnableEventLog bool
	SystemFee      map[string]int64
	GasLimit       uint64
	GasPrice       uint64
	DataDir        string
}

type ConsensusConfig struct {
	EnableConsensus bool
	MaxTxInBlock    uint
}

type P2PRsvConfig struct {
	ReservedPeers []string `json:"reserved"`
	MaskPeers     []string `json:"mask"`
}

type P2PNodeConfig struct {
	ReservedPeersOnly         bool
	ReservedCfg               *P2PRsvConfig
	NetworkMagic              uint32
	NetworkId                 uint32
	NetworkName               string
	NodePort                  uint
	NodeConsensusPort         uint
	DualPortSupport           bool
	IsTLS                     bool
	CertPath                  string
	KeyPath                   string
	CAPath                    string
	HttpInfoPort              uint
	MaxHdrSyncReqs            uint
	MaxConnInBound            uint
	MaxConnOutBound           uint
	MaxConnInBoundForSingleIP uint
}

type RpcConfig struct {
	EnableHttpJsonRpc bool
	HttpJsonPort      uint
	HttpLocalPort     uint
}

type RestfulConfig struct {
	EnableHttpRestful bool
	HttpRestPort      uint
	HttpCertPath      string
	HttpKeyPath       string
}

type WebSocketConfig struct {
	EnableHttpWs bool
	HttpWsPort   uint
	HttpCertPath string
	HttpKeyPath  string
}

type OntologyConfig struct {
	Genesis   *GenesisConfig
	Common    *CommonConfig
	Consensus *ConsensusConfig
	P2PNode   *P2PNodeConfig
	Rpc       *RpcConfig
	Restful   *RestfulConfig
	Ws        *WebSocketConfig
}

func NewOntologyConfig() *OntologyConfig {
	return &OntologyConfig{
		Genesis: MainNetConfig,
		Common: &CommonConfig{
			LogLevel:       DEFAULT_LOG_LEVEL,
			EnableEventLog: DEFAULT_ENABLE_EVENT_LOG,
			SystemFee:      make(map[string]int64),
			GasLimit:       DEFAULT_GAS_LIMIT,
			DataDir:        DEFAULT_DATA_DIR,
		},
		Consensus: &ConsensusConfig{
			EnableConsensus: true,
			MaxTxInBlock:    DEFAULT_MAX_TX_IN_BLOCK,
		},
		P2PNode: &P2PNodeConfig{
			ReservedCfg:               &P2PRsvConfig{},
			ReservedPeersOnly:         false,
			NetworkId:                 NETWORK_ID_MAIN_NET,
			NetworkName:               GetNetworkName(NETWORK_ID_MAIN_NET),
			NetworkMagic:              GetNetworkMagic(NETWORK_ID_MAIN_NET),
			NodePort:                  DEFAULT_NODE_PORT,
			NodeConsensusPort:         DEFAULT_CONSENSUS_PORT,
			DualPortSupport:           true,
			IsTLS:                     false,
			CertPath:                  "",
			KeyPath:                   "",
			CAPath:                    "",
			HttpInfoPort:              DEFAULT_HTTP_INFO_PORT,
			MaxHdrSyncReqs:            DEFAULT_MAX_SYNC_HEADER,
			MaxConnInBound:            DEFAULT_MAX_CONN_IN_BOUND,
			MaxConnOutBound:           DEFAULT_MAX_CONN_OUT_BOUND,
			MaxConnInBoundForSingleIP: DEFAULT_MAX_CONN_IN_BOUND_FOR_SINGLE_IP,
		},
		Rpc: &RpcConfig{
			EnableHttpJsonRpc: true,
			HttpJsonPort:      DEFAULT_RPC_PORT,
			HttpLocalPort:     DEFAULT_RPC_LOCAL_PORT,
		},
		Restful: &RestfulConfig{
			EnableHttpRestful: true,
			HttpRestPort:      DEFAULT_REST_PORT,
		},
		Ws: &WebSocketConfig{
			EnableHttpWs: true,
			HttpWsPort:   DEFAULT_WS_PORT,
		},
	}
}

func (this *OntologyConfig) GetBookkeepers() ([]keypair.PublicKey, error) {
	var bookKeepers []string
	switch this.Genesis.ConsensusType {
	case CONSENSUS_TYPE_VBFT:
		for _, peer := range this.Genesis.VBFT.Peers {
			bookKeepers = append(bookKeepers, peer.PeerPubkey)
		}
	case CONSENSUS_TYPE_DBFT:
		bookKeepers = this.Genesis.DBFT.Bookkeepers
	case CONSENSUS_TYPE_SOLO:
		bookKeepers = this.Genesis.SOLO.Bookkeepers
	default:
		return nil, fmt.Errorf("Does not support %s consensus", this.Genesis.ConsensusType)
	}

	pubKeys := make([]keypair.PublicKey, 0, len(bookKeepers))
	for _, key := range bookKeepers {
		pubKey, err := hex.DecodeString(key)
		k, err := keypair.DeserializePublicKey(pubKey)
		if err != nil {
			return nil, fmt.Errorf("Incorrectly book keepers key:%s", key)
		}
		pubKeys = append(pubKeys, k)
	}
	keypair.SortPublicKeys(pubKeys)
	return pubKeys, nil
}

func (this *OntologyConfig) GetDefaultNetworkId() (uint32, error) {
	defaultNetworkId, err := this.getDefNetworkIDFromGenesisConfig(this.Genesis)
	if err != nil {
		return 0, err
	}
	mainNetId, err := this.getDefNetworkIDFromGenesisConfig(MainNetConfig)
	if err != nil {
		return 0, err
	}
	polaridId, err := this.getDefNetworkIDFromGenesisConfig(PolarisConfig)
	if err != nil {
		return 0, err
	}
	switch defaultNetworkId {
	case mainNetId:
		return NETWORK_ID_MAIN_NET, nil
	case polaridId:
		return NETWORK_ID_POLARIS_NET, nil
	}
	return defaultNetworkId, nil
}

func (this *OntologyConfig) getDefNetworkIDFromGenesisConfig(genCfg *GenesisConfig) (uint32, error) {
	var configData []byte
	var err error
	switch this.Genesis.ConsensusType {
	case CONSENSUS_TYPE_VBFT:
		configData, err = json.Marshal(genCfg.VBFT)
	case CONSENSUS_TYPE_DBFT:
		configData, err = json.Marshal(genCfg.DBFT)
	case CONSENSUS_TYPE_SOLO:
		return NETWORK_ID_SOLO_NET, nil
	default:
		return 0, fmt.Errorf("unknown consensus type:%s", this.Genesis.ConsensusType)
	}
	if err != nil {
		return 0, fmt.Errorf("json.Marshal error:%s", err)
	}
	data := sha256.Sum256(configData)
	return binary.LittleEndian.Uint32(data[0:4]), nil
}
