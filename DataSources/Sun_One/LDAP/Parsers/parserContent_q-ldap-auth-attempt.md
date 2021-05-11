#### Parser Content
```Java
{
Name = q-ldap-auth-attempt
    Vendor = Sun One
    Product = LDAP
    Lms = QRadar
    DataType = "authentication-attempt"
    TimeFormat = "dd/MM/yyyy:HH:mm:ss.SSS Z"
    Conditions = [ """ BIND """, """ resultCode=""", """ clientConnectionPolicy=""" ]
    Fields = [
      """\[({time}\d{1,100}\/\w+\/\d\d\d\d:\d\d:\d\d:\d\d\.\d{1,100}\s{0,100}(\+|\-)\d{1,100})\]""",
      """exabeam_startTime=({time}\d{1,100})""",
      """({host}[\w\-\.]+)\s{1,100}BIND RESULT """,
      """({dest_host}[\w\-\.]+)\s{1,100}BIND RESULT """,
      """\Wuid=({user}[^\s,"]+)""",
      """\WauthType="{1,20}({auth_type}[^"]+?)"{1,20}(\s{1,100}\w+=|\s{0,100}$)"""
      """\WresultCode=({outcome}\d{1,100})""",
      """\WtargetHost="{1,20}({dest_host}[^"]+?)"{1,20}(\s{1,100}\w+=|\s{0,100}$)""",
      """\WtargetPort=({dest_port}\d{1,100})""",
      """\WtargetProtocol="{1,20}({protocol}[^"]+?)"{1,20}(\s{1,100}\w+=|\s{0,100}$)""",
      """\WrequesterIP="({src_ip}[a-fA-F\d.:]+)""",
      """\WinstanceName="({host}[^"]+)""",
      """\WauthDN="({user_ou}[^"]+)""",
    ]
  }
```