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
      """\shost_masked="({host}[^",]+)""",
      """\sduser="?(?:None|({user}[^",]+))""",
      """\sdvc_masked="({host}[^",]+)""",
      """\shost_ip_masked="({host}[^",]+)""",
      """\shost_masked="({host}[^",]+)""",
      """\ssrc_masked="({host}[^",]+)""",
      """\sdst_masked="({dest_ip}[^",]+)""",
      """\sdhost="({dest_host}[^",]+)""",
      """\sshost="({src_host}[^",]+)""",
      """\ssrc_masked="({src_ip}[^",]+)""",
      """\scs3="({additional_info}[^",]+)""",
      """\scategory="({alert_name}[^",]+)""",
      """\scef_severity=({alert_severity}\w+)""",
      """\sseverity=({alert_severity}\w+)""",
      """\scef_signature=({alert_id}\d{1,100})""",
    ]
    DupFields = ["alert_name->alert_type"]
  }
```