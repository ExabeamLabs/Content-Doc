#### Parser Content
```Java
{
Name = q-unix-audispd-logon
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """audispd:""", """ type=USER_""", """ res=""", """ acct=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\s({host}[\w\-.]{1,2000})\s{1,100}audispd:""",
    """msg=audit\(({time}\d{1,100})\.\d{1,100}:\d{1,100}\):""",
    """\snode=({host}[\w\.-]{1,2000})\s""",
    """\sacct="\(?(unknown|({user}.+?))\)?"\s{1,100}\w+=""",
    """\shostname=(\?|({src_host}[\w\.-]{1,2000}))\s{1,100}\w+=""",
    """\saddr=(\?|({src_ip}[\d\.:a-fA-F]{1,2000}))\s{1,100}\w+=""",
    """\sterminal=(\?|({logon_type_text}.+?))\s{1,100}\w+=""",
    """\sexe="({auth_process}.+?)"\s{1,100}\w+=""",
    """\stype=({audispd_type}USER_\S+)\s{1,100}\w+=""",
    """\sres=({outcome}.+?)('\s{0,100}$|'?\s{1,100}\w+=)""",
  ]
  DupFields=[ "host->dest_host" ]
}
```