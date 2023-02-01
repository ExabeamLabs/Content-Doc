#### Parser Content
```Java
{
Name = cef-palo-alto-userid-login
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Splunk
  DataType = "authentication-successful"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """CEF:0|Palo Alto Networks|""", """|USERID|login|""" ]
  Fields = [
    """\sdvchost=({host}[\w.-]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\srt=({time}\w{3}\s\d{2}\s\d{4}\s(\d{2}:){2}\d{2})\s""",
    """\sduser=(({domain}[^\\]{1,2000})\\+)?(|({user}[^\\\s]{1,2000}))\s{1,100}(\w+=|$)""",
    """\sPanOSUserIdentifiedBySource=({user_email}[^@\s]{1,2000}@[^\s=]{1,2000}?)\s"""
    """\ssrc=(0.0.0.0|({src_ip}[A-Fa-f\d.:]{1,2000}))\s{1,100}(\w+=|$)""",
    """\sdst=(0.0.0.0|({dest_ip}[A-Fa-f\d.:]{1,2000}))\s{1,100}(\w+=|$)""",
    """\scs1=({auth_method}[^=]{1,2000}?)\scs1Label=MFAFactorType"""
  ]


}
```