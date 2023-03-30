#### Parser Content
```Java
{
Name = kv-sensormatik-badge-access
  Vendor = Sensormatik
  Product = Sensormatik
  Lms = Splunk
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Sensormatik_PersonalLog""", """Door="""", """Direction=""" ]
  Fields = [
    """Status="{1,20}({outcome}[^"]{1,2000})"""",
    """Date="{1,20}({time}[^"\.]{1,2000})""",
    """Id="{1,20}({badge_id}\d{1,2000})""""
    """Personnel="{1,20}({last_name}[^,]{1,2000}), ({first_name}[^"]{1,2000})"""",
    """Door="{1,20}({location_door}[^"]{1,2000})"""",
    """Direction="{1,20}({direction}[^"]{1,2000})"""",
    """Text1="{1,20}({additional_info}[^"]{1,2000})""""
  ]


}
```