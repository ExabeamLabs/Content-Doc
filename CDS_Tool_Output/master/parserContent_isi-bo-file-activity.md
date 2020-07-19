#### Parser Content
```Java
{
Name = isi-bo-file-activity
  Vendor = BusinessObject
  Lms = Splunk
  DataType = "file-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd-HH.mm.ss"
  Conditions = [ """isi_bo""", """<custom_condition_cont-7495>""" ]
  Fields = [
    """"({time}\d\d\d\d-\d\d-\d\d-\d\d\.\d\d\.\d\d)[^"]*","({user}[^"]+?)","({session_id}[^"]+?)",({accesses}\d+),"(|({file_path}[^"]+?))","(-|({bytes}\d+))"""
  ]
}

{
    Name = s-tanium-security-alert-2
    Vendor = Tanium
    Product = Endpoint Platform
    Lms = Default
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """trace_process_table_id""", """Timestamp""", """Computer Name""", """Computer IP""" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]+)""",
      """"Timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)"""", 
      """"User Name":"({user}[^"]+?)"""",
      """"User Id":"({user}[^"]+?)"""",
      """"User Domain":"({domain}[^"]+?)"""",
      """"user\\":\\"(({domain}[^"\\]+)\\+)?({user}[^"]+?)\\*"""",
      """"Priority":"({alert_severity}[^"]+)"""",
      """"Event Name":"({alert_name}[^"]+)"""",
      """"Event Name":"({alert_type}[^"]+)"""",
      """"Event Id":"({alert_id}[^"]+)"""",
      """"Computer Name":"({src_host}[^"]+?)"""",
      """"Computer IP":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
      """"fullpath\\":\\"({malware_url}[^"]+?)\\*"""",
      """"name\\":\\"({file_name}[^"]+?)\\*"""",
      """"md5\\":\\"({md5}[^"]+?)\\*"""",
      """"payload=\{({additional_info}.+?[^\\]")\}"""
    ]
  }
```