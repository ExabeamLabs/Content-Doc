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
    """,({time}\d\d\/\d\d\/\d\d\d\d,\d\d:\d\d:\d\d),IAS,({auth_server}[^\,]+),""",
    """,4130,({domain}[^\/]+)\\({user}[^\,]+),""",
    """,4127,({auth_type}\d+),""",
    """,({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),4116,""",
    """,25,\d+\s+\d+\s+({host}[^\s]+)\s""",
    """,30,[^:]+\:({network}[^\,]+),""",
    """,31,({src_mac}[^\,]+),"""
  ]
}
```