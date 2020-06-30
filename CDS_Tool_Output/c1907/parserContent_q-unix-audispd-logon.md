#### Parser Content
```Java
{
Name = q-unix-audispd-logon
  Vendor = Unix
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "epoch_sec"
  Conditions = [ """audispd:""", """ type=USER_""", """ res=""", """ acct=""" ]
  Fields = [
    """msg=audit\(({time}\d+)\.\d+:\d+\):""",
    """\snode=({host}[\w\.-]+)\s""",
    """\sacct="\(?(unknown|({user}.+?))\)?"\s+\w+=""",
    """\shostname=(\?|({src_host}[\w\.-]+))\s+\w+=""",
    """\saddr=(\?|({src_ip}[\d\.:a-fA-F]+))\s+\w+=""",
    """\sterminal=(\?|({logon_type_text}.+?))\s+\w+=""",
    """\sexe="({auth_process}.+?)"\s+\w+=""",
    """\stype=({audispd_type}USER_\S+)\s+\w+=""",
    """\sres=({outcome}.+?)('\s*$|\s+\w+=)""",
  ]
  DupFields=[ "host->dest_host" ]
}
```