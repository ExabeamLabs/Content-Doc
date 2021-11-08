#### Parser Content
```Java
{
Name = s-ironport-email-av-result
    Vendor = Cisco
    Product = IronPort Email
    Lms = Direct
    DataType = "dlp-email-alert"
    TimeFormat = "epoch"
    Conditions = [ """MID """, """ antivirus """ ]
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
      """exabeam_indexTime=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
      """\srt=({time}\d{1,100})""",  
      """MID ({alert_id}\d{1,100})""",
      """ antivirus ({malware_score}.+?)(\s{1,100}\w+=|\s{0,100}$)"""
      """ antivirus -[^-]{0,2000}?- Result '({malware_score}.+?)'"""
    ]
  }
```