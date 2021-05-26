#### Parser Content
```Java
{
Name = msnetwork-nac-logon
  Vendor = Microsoft
  Product = Microsoft NPS
  Lms = Direct
  DataType = "windows-nac-logon"
  TimeFormat = "MM/dd/yyyy,HH:mm:ss"
  Conditions = [ """,IAS,""", """,4136,1,4142,0"""]
  Fields = [
    """,({time}\d\d\/\d\d\/\d\d\d\d,\d\d:\d\d:\d\d),IAS,({auth_server}[^\,]{1,2000}),""",
    """,4130,({domain}[^\/]{1,2000})\\({user}[^\,]{1,2000}),""",
    """,4127,({auth_type}\d{1,100}),""",
    """,({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),4116,""",
    """,25,\d{1,100}\s{1,100}\d{1,100}\s{1,100}({host}[^\s]{1,2000})\s""",
    """,30,[^:]{1,2000}\:({network}[^\,]{1,2000}),""",
    """,31,({src_mac}[^\,]{1,2000}),"""
  ]
}
```