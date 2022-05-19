#### Parser Content
```Java
{
Name = cylance-alert-2
  Vendor = BlackBerry
  Product = BlackBerry Protect
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """destinationServiceName =CylanceProtect""", """externalID="""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\d{1,100}\s{1,100}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z)\s{1,100}""",
    """\WexternalID=({src_host}[\w.\-]{1,2000})""",
    """\Woutcome=({outcome}[^\s]{1,2000})""",
    """\Wcat=(|({alert_type}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """Security Alert Detected by.*?Category \[({alert_type}[^\]\[,]{1,2000}?)\]"""
    """Security Alert Detected by.*?SubCategory \[({category}[^\]\[,]{1,2000}?)\]"""
    """\Wfname=(|({malware_url}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wfname=(|({process}({process_directory}(?:(\w+:)*([\\\/]{1,2000}[^\\\/"]{1,2000}?)+?)?[\\\/]{1,2000})({process_name}[^"\\\/]{1,2000}?)))\s{1,100}(\w+=|$)""",
    """\Wproto=(|({file_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wmsg=(|({additional_info}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[a-fA-F:\d.]{1,2000})""",
    """"cylance_score":({alert_severity}[^",]{1,2000})""",
    """\WdestinationServiceName =(|({device_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"md5":"({md5}[^"]{1,2000})""",
    """"name":"({file_name}[^"]{1,2000})"""",
    """"sha256":"({file_hash}[^"]{1,2000})""""
  ]
  DupFields = [ "alert_type->alert_name", "file_name->name_at", "file_hash->sha256_at" ]


}
```