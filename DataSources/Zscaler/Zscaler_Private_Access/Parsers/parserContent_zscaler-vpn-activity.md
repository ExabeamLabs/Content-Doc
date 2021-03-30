#### Parser Content
```Java
{
Name = zscaler-vpn-activity
  Vendor = Zscaler
  Product = Zscaler Private Access
  Lms = Direct
  DataType = "vpn-login"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """ZENBytesRxConnector""" , """ZENTotalBytesTxConnector""" , """ZENBytesTxConnector""", """TimestampZENLastRxClient""", """DoubleEncryption"""]
  Fields = [
    """Host":\s*"({host}[^"]+)"""",
    """({time}\w{3}\s\d+\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
    """Username":\s*"(({user_email}[^@]+@[^"]*)|({user}[^"]+))"""",
    """IPProtocol":\s*({protocol}[^,]+),"""
    """ClientPublicIP":\s*"({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""",
    """ServerIP":\s*"({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""",
    """ConnectorPort":\s*({src_port}\d+),""",
    """ServerPort":\s*({dest_port}\d+),""",
    """Application":\s*"\s*({app}[^"]+)"""",
    """AppGroup":\s*"\s*({activity_type}[^"]+)""""
    """ZENTotalBytesRxConnector":\s*({bytes_in}\d+),""",
    """ZENTotalBytesTxConnector":\s*({bytes_out}\d+),""",
    """Policy":\s*"\s*({policy}[^"]+)"""",
    """ConnectionStatus":\s*"({outcome}[^"]+)""""
  ]
}
```