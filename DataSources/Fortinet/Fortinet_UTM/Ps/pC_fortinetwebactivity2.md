#### Parser Content
```Java
{
Name = fortinet-web-activity-2
  Vendor = Fortinet
  Product = Fortinet UTM
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "epoch"
  Conditions = [ """ad.subtype=""","""ad.eventtype=""", """ad.direction=""", """deviceExternalId=""", """logver""" ]
  Fields = [
    """\sad.eventtime=({time}\d{1,100})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\ssrc=({src_ip}[a-fA-F\d:.]{1,2000})""",
    """\sspt=({src_port}\d{1,100})""",
    """\sdst=({dest_ip}[a-fA-F\d:.]{1,2000})""",
    """\sdpt=({dest_port}\d{1,100})""",
    """\sact=({action}[^\s]{1,2000})""",
    """\sdhost=({web_domain}[^\s]{1,2000})""",
    """request=((\w+:\/{1,20})?({web_domain}[^\s\/]{1,2000})({uri_path}\/[^\s\?]{0,2000})?({uri_query}\?[^\s]{0,2000})?)\s{1,100}[\w.]{1,2000}=""",
    """\sout=({bytes_out}\d{1,100})""",
    """\sin=({bytes_in}\d{1,100})""",
    """\smsg=({additional_info}[^=]{1,2000}?)\s{1,100}([\w.]{1,2000}=|$)""",
    """\sact=blocked[^\n]{1,2000}?msg=({reason}[^=]{1,2000}?)\s{1,100}([\w.]{1,2000}=|$)""",
    """\sproto=({protocol}[^\s]{1,2000})\s{1,100}\w+=""",
    """\sad.direction=({direction}[^=]{1,2000}?)\s{1,100}\w+=""",
    """referralurl=({referrer}[^\s]{1,2000})"""
    """\sad.policyid=({policy_id}[^\s]{1,2000})""",
    """\sduser=({user}[^\s]{1,2000})""",
    """\sad.agent=({user_agent}[^=]{1,2000}?)\s{1,100}[\w.]{1,2000}=""",
    """requestContext=({category}[^=]{1,2000}?)\s{1,100}([\w.]{1,2000}=|$)"""
  ]


}
```