#### Parser Content
```Java
{
Name = ssh-vectra-meta-data
  DataType = "remote-logon"
  Conditions = [ """vectra_metadata_ssh""", """METADATA_SSH""" ]
  Fields = ${VectraParserTemplates.vectra-meta-data.Fields} [
    """server="+({server_version}[^"]+)"+""",
    """client="+({client_version}[^"]+)"+""",
    """cipher_alg="+({cipher_algorithm}[^"]+)"+""",
    """compression_alg="+(none|({compression_algotithm}[^"]+))"+"""
  ]
}
${VectraParserTemplates.vectra-meta-data}{
  Name = rdp-vectra-meta-data
  DataType = "remote-logon"
  Conditions = [ """vectra_metadata_rdp""", """METADATA_RDP""" ]
  Fields = ${VectraParserTemplates.vectra-meta-data.Fields} [
    """result="+({outcome}[^"]+)"+"""
  ]
}

{
  Name = admanager-activity
  Vendor = ManageEngine
  Product = ADmanager
  Lms = Direct
  DataType = "member-removed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ADMP""", """Status=""" ]
  Fields = [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)\s*({host}[^\s]+)""",
    """\[Status=({status}[^]]+)\]""",
    """\[TechnicianName=(\([^[\)]+\)\s*)?({user}[^]]+)\]""",
    """\[Task=({activity}[^]]+)\]""",
    """\[ACTION=({action}[^]]+)\]""",
    """\[accountExpires=({account}[^]]+)\]""",
    """\[Template Name=({event_name}[^]]+)\]""",
    """\[Object Name=({object}[^]]+)\]""",
    """\[Domain Name=({domain_name}[^]]+)\]""",
    """\[memberOf=\[({group_name}[^]]+)]]""",
    """\[Object Name=(\([^[\)]+\)\s*)?({account}[^]]+)\]""",
  ]
}
```