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
    """Host":\s{0,100}"({host}[^"]+)"""",
    """({time}\w{3}\s\d{1,100}\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
    """Username":\s{0,100}"(({user_email}[^@]+@[^"]*)|({user}[^"]+))"""",
    """IPProtocol":\s{0,100}({protocol}[^,]+),"""
    """ClientPublicIP":\s{0,100}"({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""",
    """ServerIP":\s{0,100}"({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""",
    """ConnectorPort":\s{0,100}({src_port}\d{1,100}),""",
    """ServerPort":\s{0,100}({dest_port}\d{1,100}),""",
    """Application":\s{0,100}"\s{0,100}({app}[^"]+)"""",
    """AppGroup":\s{0,100}"\s{0,100}({activity_type}[^"]+)""""
    """ZENTotalBytesRxConnector":\s{0,100}({bytes_in}\d{1,100}),""",
    """ZENTotalBytesTxConnector":\s{0,100}({bytes_out}\d{1,100}),""",
    """Policy":\s{0,100}"\s{0,100}({policy}[^"]+)"""",
    """ConnectionStatus":\s{0,100}"({outcome}[^"]+)""""
  ]
}
```