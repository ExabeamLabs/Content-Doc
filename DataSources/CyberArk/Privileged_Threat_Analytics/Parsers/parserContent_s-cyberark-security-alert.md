#### Parser Content
```Java
{
Name = s-cyberark-security-alert
    Vendor = CyberArk
    Product = Privileged Threat Analytics
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "epoch"
    Conditions = [ """app="cyberark:pta"""", """deviceCustomDate1=""",  ]
    Fields = [
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d\:\d\d)""",
      """"deviceCustomDate1(":\s{1,100}"|=)({time}\d{1,100}).*?"deviceCustomDate1Label(": "|=)DetectionDate"""",
      """"deviceCustomDate1Label(": "|=)DetectionDate".*?"deviceCustomDate1(":\s{1,100}"|=)({time}\d{1,100})""",
      """\shost_masked="({host}[^",]{1,2000})""",
      """\sduser="?(?:None|({user}[^",]{1,2000}))""",
      """\sdvc_masked="({host}[^",]{1,2000})""",
      """\shost_ip_masked="({host}[^",]{1,2000})""",
      """\shost_masked="({host}[^",]{1,2000})""",
      """\ssrc_masked="({host}[^",]{1,2000})""",
      """\sdst_masked="({dest_ip}[^",]{1,2000})""",
      """\sdhost="({dest_host}[^",]{1,2000})""",
      """\sshost="({src_host}[^",]{1,2000})""",
      """\ssrc_masked="({src_ip}[^",]{1,2000})""",
      """\scs3="({additional_info}[^",]{1,2000})""",
      """\scategory="({alert_name}[^",]{1,2000})""",
      """\scef_severity=({alert_severity}\w+)""",
      """\sseverity=({alert_severity}\w+)""",
      """\scef_signature=({alert_id}\d{1,100})""",
    ]
    DupFields = ["alert_name->alert_type"]
  }
```