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
    """Host":\s{0,100}"({host}[^"]{1,2000})"""",
    """({time}\w{3}\s\d{1,100}\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
    """Username":\s{0,100}"(({user_email}[^@]{1,2000}@[^"]{0,2000})|({user}[^"]{1,2000}))"""",
    """IPProtocol":\s{0,100}({protocol}[^,]{1,2000}),"""
    """ClientPublicIP":\s{0,100}"({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""",
    """ServerIP":\s{0,100}"({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""",
    """ConnectorPort":\s{0,100}({src_port}\d{1,100}),""",
    """ServerPort":\s{0,100}({dest_port}\d{1,100}),""",
    """Application":\s{0,100}"\s{0,100}({app}[^"]{1,2000})"""",
    """AppGroup":\s{0,100}"\s{0,100}({activity_type}[^"]{1,2000})""""
    """ZENTotalBytesRxConnector":\s{0,100}({bytes_in}\d{1,100}),""",
    """ZENTotalBytesTxConnector":\s{0,100}({bytes_out}\d{1,100}),""",
    """Policy":\s{0,100}"\s{0,100}({policy}[^"]{1,2000})"""",
    """ConnectionStatus":\s{0,100}"({outcome}[^"]{1,2000})""""
  ]
}
```