#### Parser Content
```Java
{
Name = unix-audispd-remote-logon
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "epoch"
  Conditions = [ """ audispd""", """ type=USER_LOGIN""", """ res=""", """ msg=""" ]
  Fields = [
    """({host}[\w\-\.]{1,2000})\saudispd""",
    """\smsg=audit\(({time}\d{1,10})\.\d{1,10}:\d{1,10}\):""",
    """\snode=({host}[\w\.-]{1,2000})\s""",
    """\sacct="\(?(unknown|({user}[^"]{1,2000}?))\)?"""",
    """\shostname=(\?|({src_host}[\w\.-]{1,2000}))\s{1,100}\w+=""",
    """\saddr=(\?|({src_ip}[\d\.:a-fA-F]{1,2000}))\s{1,100}\w+=""",
    """\sterminal=(\?|({logon_type_text}[^=]{1,2000}?))\s{1,100}\w+=""",
    """\sexe="({auth_process}[^"]{1,2000}?)"""",
    """\stype=({audispd_type}USER_\S+)\s{1,100}\w+=""",
    """\sres=({outcome}[^\(\)]{1,2000}?)('\s{0,100}$|'?\s{1,100}\w+=)""",
    """({event_code}ssh)""",
    """({event_name}USER_LOGIN)"""
  ]
  DupFields=[ "host->dest_host" ]


}
```