#### Parser Content
```Java
{
Name = crowdstrike-security-alert-4
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "alert"
    TimeFormat = "epoch"
    Conditions = [ """"event_simpleName":"DllInjection"""", """"timestamp":"""" ]
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
      """"timestamp":"({time}\d{1,100})"""",
      """\Whostname=(|({host}[^,=]{1,2000}?)),?(\s{1,100}\w+=|\s{0,100}\})""",
      """"InjectedDll":"({malware_file_name}[^"]{1,2000})""",
      """"event_simpleName":"({alert_name}[^"]{1,2000})""",
      """"id":"({alert_id}[^"]{1,2000})""",
    ]
    DupFields = [ "alert_name->alert_type","alert_name->event_code" ]
  

}
```