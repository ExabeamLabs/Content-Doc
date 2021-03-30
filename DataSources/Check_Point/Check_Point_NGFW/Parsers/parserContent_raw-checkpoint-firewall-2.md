#### Parser Content
```Java
{
Name = raw-checkpoint-firewall-2
  DataType = "network-connection"
  Conditions = [ """product=VPN-1 & FireWall-1""", """product:""", """action:"""" ]
  Fields = ${CheckpointParserTemplates.checkpoint-firewall-1.Fields}[
    """\Wuser:"({user_firstname}[\w\s]+[^\s,\(])\s+({user_lastname}[^\s,\(]+)\s*\(({user}.+?)(\)|@)"""
  ] 
}
```