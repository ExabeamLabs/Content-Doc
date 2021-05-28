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
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z\s{0,100}({host}[\w\-.]{1,2000})\s{0,100}LEEF""",
    """(LEEF|CEF):([^\|]{0,2000}?\|){4}({event_code}\d{1,100})""",
    """\s{1,100}usrName=({user}.+?)\s{0,100}src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{0,100}""",
    """\s{1,100}File=({file_path}.+?)\s{0,100}Safe=""",
    """\s{1,100}File=({file_parent}.+?)\\[^\\]{1,2000}\s{0,100}Safe=""",
    """\s{1,100}File=[^=]{0,2000}\\({file_name}[^=]{1,2000}?)\s{0,100}Safe=""",
    """\s{1,100}File=[^=]{0,2000}\\[^=]{0,2000}\.({file_ext}[^=.\s\\]{1,100}?)\s{0,100}Safe=""",
    """({file_type}(?i)file)""",
    """\s{1,100}File=({object}.+?)\s{0,100}Safe=({resource}.+?)\s{0,100}Location""",
    """Action=({activity}.+?)\s{0,100}EventMessage""",
    """({app}Cyber-Ark\|Vault)""",
    """ProcessName=({process_name}[^;=]{1,2000})""",
  ]
  DupFields = [ "activity->accesses" ]
}
```