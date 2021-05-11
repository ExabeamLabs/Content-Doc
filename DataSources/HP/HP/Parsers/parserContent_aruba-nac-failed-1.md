#### Parser Content
```Java
{
Name = aruba-nac-failed-1
  DataType = "nac-failed-logon"
  Conditions = [ """CEF:""", """"ident":""", """"extradata":""", """"ttam_file":""", """"ttam_reporter":""", """User Authentication failed.""", """method"""]
  Fields = ${ArubaParserTemplates.cef-aruba-nac-logon-2.Fields}[
    """authmethod\\*=({auth_type}[^=]+)\s{1,100}\w+\\*=""",
  ]
}
cef-aruba-nac-logon-2 = {
    Vendor = HP
    Product = Aruba Mobility Master
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""",
      """"host":"({host}[^"]+)"""",
      """MAC\\*=({src_mac}([a-fA-F\d]{2}[-:]){5}[a-fA-F\d]{2})""",
      """usermac\\*=({src_mac}[\w:]+)""",
      """username\\*=({user_email}({user}[^@]+)@({domain}[^\s]+))""",
      """Authentication Succeeded for User ({user}[^,]+)""",
      """Logged in from\s({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\sport\s({src_port}\d{1,100}))?""",
      """Connecting to\s({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\sport\s({dest_port}\d{1,100}))?""",
      """IP\\*=(0.0.0.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
      """\smethod\\*=({auth_type}[^=]+)\s{1,100}\w+\\*=""",
      """server\\*=({auth_server}[^"]+)"""",
      """servername\\*=({auth_server}[^=]+)\s{1,100}\w+\\*=""",
      """username\\*=({user}\w+)\s"""
    ]

```