#### Parser Content
```Java
{
Name = fortinet-network-connection
  Vendor = Fortinet
  Product = Fortinet Enterprise Firewall
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "epoch"
  Conditions = [ """type=""", """traffic""", """action=""", """service=""", """date=""" ]
  Fields = [
    """eventtime=({time}\d{1,10})""",
    """\Wdevname="?({host}[^"]{1,2000}?)"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrcip=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdstip=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wsrcport=({src_port}\d{1,100})""",
    """\Wdstport=({dest_port}\d{1,100})""",
    """\Wdstintf="{1,20}({dest_interface}[^"]{1,2000})""",
    """\Wsrcintf="{1,20}({src_interface}[^"]{1,2000})""",
    """\Wuser="{1,20}((?:host\/({src_host}[^"]{1,2000}))|({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})|({user}[^"]{1,2000}))""",
    """\Wsentbyte=({bytes_out}\d{1,100})""",
    """\Wrcvdbyte=({bytes_in}\d{1,100})""",
    """\Waction="{0,20}({action}[^"]{1,2000}?)"{0,20}(\s{1,100}\w{1,100}=|\s{0,100}$)""",
    """\Wsentpkt=({packets_sent}\d{1,100})""",
    """policyid=({policy_id}\d{1,100})"""
    """\Wproto=({protocol}\d{1,100})""",
    """\Wservice="{0,20}({protocol}[^"\/\s-]{1,2000}?)(\_\d{1,5})?"""",
    """\Wsrcintfrole="{1,20}(undefined|({src_interface_role}[^"]{1,2000}))"{1,20}""",
    """\Wdstintfrole="{1,20}(undefined|({dest_interface_role}[^"]{1,2000}))"{1,20}""",
    """\Wsrccountry="(Reserved|({src_country}[^"]{1,2000}))"""",
    """\Wdstcountry="(Reserved|({dest_country}[^"]{1,2000}))"""",
    """\ssrcname="{0,10}({src_host}[\w.-]{1,2000}?)""""
  ]
  DupFields = [ "action->outcome" ]


}
```