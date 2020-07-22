#### Parser Content
```Java
{
Name = zscaler-activity
  Vendor = Zscaler
  Product = Zscaler Internet Access
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = ["""InternalReason""" , """ClientPrivateIP""", """ConnectorZENSetupTime"""]
  Fields = [
     """Host":\s*"({host}[^"]+)"""",
     """({time}\w{3}\s\d+\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
     """Username":\s*"(({user_email}[^@]+@[^\s]*)"|({user}[^\s]+))(\s|,!?)""",
     """IPProtocol":\s*({protocol}[^"]+),"""
     """ClientPublicIP":\s*"({src_ip}[^"]+)""",
     """ServerIP":\s*"({dest_ip}[^"]+)"""",
     """ConnectorPort":\s*({src_port}[^\s]+),""",
     """ServerPort":\s*({dest_port}[^\s]+),""",
     """Application":\s*"\s*({app}[^"\s].+?)\s*"""",
     """AppGroup":\s*"\s*({activity_type}[^"].+?)\s*""""
     """ZENTotalBytesRxConnector":\s*({bytes_in}[^,]+),""",
     """ZENTotalBytesTxConnector":\s*({bytes_out}[^,]+),""",
     """Policy":\s*"\s*({policy}[^"]+)"""",
     """ConnectionStatus":\s*"({outcome}[^"]+)""""
  ]
}
```