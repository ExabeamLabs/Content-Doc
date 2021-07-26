#### Parser Content
```Java
{
Name = r-syslog-physical-badge-access
    Vendor = Siemens
  Product = Siemens
    Lms = Direct
    DataType = "physical-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["""%SIEMENS_FUSION_AC:""","""exabeam_raw"""]
    Fields = [
      """exabeam_host=({host}[^\s]{1,2000})""",
      """%SIEMENS_FUSION_AC:(.+?(\^){2}){1}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """%SIEMENS_FUSION_AC:(.+?(\^){2}){4}({employee_id}(NE-)?\d{1,100})""",
      """%SIEMENS_FUSION_AC:(.+?(\^){2}){6}({badge_id}\d{1,100})""",
      """%SIEMENS_FUSION_AC:(.+?(\^){2}){8}({outcome}.+?)(\^)+""",
      """%SIEMENS_FUSION_AC:(.+?(\^){2}){10}({location_door}.+?)(\^)+""",
      """%SIEMENS_FUSION_AC:(.+?(\^){2}){12}({location_building}.+?)(\^)+""",
      """%SIEMENS_FUSION_AC:(.+?(\^){2}){14}({location_city}.+?)(\^)+"""
    ]
  }
```