#### Parser Content
```Java
{
Name = gallagher-badge-access-denied
  Vendor = Gallagher
  Product = Gallagher Badge Access
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "dd/MM/yyyy HH:mm:ss a"
  Conditions = ["""Card number (""", """denied""", """<custom_condition_cont7802>"""]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """({time}\d\d\/\d\d\/\d{4}\s\d\d:\d\d:\d\d\s\S\S)""",
    """(?:\d\d\/\d\d\/\d{4}\s\d\d:\d\d:\d\d\s\S\S)","({description}[^"]+)"""",
    """(?:\d\d\/\d\d\/\d{4}\s\d\d:\d\d:\d\d\s\S\S)","[^"]+","({location_full}[^"]+)",""",
    """(?:\d\d\/\d\d\/\d{4}\s\d\d:\d\d:\d\d\s\S\S)",("[^"]+",){2}"({badge_id}[^"]+)",""",
    """(?:\d\d\/\d\d\/\d{4}\s\d\d:\d\d:\d\d\s\S\S)",("[^"]+",){3}"({log_type}[^"]+)",""",
    """(?:\d\d\/\d\d\/\d{4}\s\d\d:\d\d:\d\d\s\S\S)",("[^"]+",){4}"({log_source}[^"]+)",""",
    """(?:\d\d\/\d\d\/\d{4}\s\d\d:\d\d:\d\d\s\S\S)",("[^"]+",){5}"({first_name}[^"]+)",""",
    """(?:\d\d\/\d\d\/\d{4}\s\d\d:\d\d:\d\d\s\S\S)",("[^"]+",){6}"({last_name}[^"]+)""",
  ]
}
```