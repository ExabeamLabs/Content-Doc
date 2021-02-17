#### Parser Content
```Java
{
Name = leef-cyberark-app-activity
  Vendor = CyberArk
  Product = CyberArk Vault
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [  """LEEF:""", """|Cyber-Ark|Vault|""", """usrName=""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z\s*({host}[\w\-.]+)\s*LEEF""",
    """(LEEF|CEF):([^\|]*?\|){4}({event_code}\d+)""",
    """\s+usrName=({user}.+?)\s*src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*""",
    """\s+File=({file_path}.+?)\s*Safe=""",
    """\s+File=({file_parent}.+?)\\[^\\]+\s*Safe=""",
    """\s+File=.*\\({file_name}.+?)\s*Safe=""",
    """\s+File=.*\\.*(?=\.)({file_ext}.+?)\s*Safe=""",
    """({file_type}(?i)file)""",
    """\s+File=({object}.+?)\s*Safe=({resource}.+?)\s*Location""",
    """Action=({activity}.+?)\s*EventMessage""",
    """({app}Cyber-Ark\|Vault)""",
    """ProcessName=({process_name}[^;=]+)""",
  ]
  DupFields = [ "activity->accesses" ]
}
```