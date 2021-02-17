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
      """\[({time}\d+\/\w+\/\d\d\d\d:\d\d:\d\d:\d\d\.\d+\s*(\+|\-)\d+)\]""",
      """exabeam_startTime=({time}\d+)""",
      """({host}[\w\-\.]+)\s+BIND RESULT """,
      """({dest_host}[\w\-\.]+)\s+BIND RESULT """,
      """\Wuid=({user}[^\s,"]+)""",
      """\WauthType="+({auth_type}[^"]+?)"+(\s+\w+=|\s*$)"""
      """\WresultCode=({outcome}\d+)""",
      """\WtargetHost="+({dest_host}[^"]+?)"+(\s+\w+=|\s*$)""",
      """\WtargetPort=({dest_port}\d+)""",
      """\WtargetProtocol="+({protocol}[^"]+?)"+(\s+\w+=|\s*$)""",
      """\WrequesterIP="({src_ip}[a-fA-F\d.:]+)""",
      """\WinstanceName="({host}[^"]+)""",
      """\WauthDN="({user_ou}[^"]+)""",
    ]
  }
```