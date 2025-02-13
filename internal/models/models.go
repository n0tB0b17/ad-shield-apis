package models

type ReqPortScan struct {
	PortRange string `json:"port_range"`
	Address   string `json:"address"`
}
