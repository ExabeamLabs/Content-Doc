#### Parser Content
```Java
{
Name = s-honeywell-physical-badge-access
    Vendor = Honeywell
    Product = Honeywell Pro-Watch
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat = "MM/dd/yyyy HH:mm:ss"
    Conditions = [  """exabeam_sourcetype=honeywell:prowatch""" ]
    Fields = [
      """exabeam_raw=([^\|]{0,2000}\|){9}({time}[^\|]{1,2000})\|""",
      """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[^\s]{1,2000})""",
      """exabeam_raw=([^\|])({employee_id}[^\|]{1,2000})\|""",
      """exabeam_raw=([^\|]{0,2000}\|){2}({last_name}[^\|]{1,2000})\|""",
      """exabeam_raw=([^\|]{0,2000}\|){3}({first_name}[^\|]{1,2000})\|""",
      """exabeam_raw=([^\|]{0,2000}\|){4}({middle_name}[^\|]{1,2000})\|""",
      """exabeam_raw=([^\|]{0,2000}\|){8}({badge_id}[^\|]{1,2000})\|""",
      """exabeam_raw=([^\|]{0,2000}\|){10}({outcome}[^\|]{1,2000})\|""",
      """exabeam_raw=([^\|]{0,2000}\|){11}({location_door}[^\|]{1,2000})\|""",
      """exabeam_raw=([^\|]{0,2000}\|){13}({location_area}[^\|]{1,2000}?)(\||\s{0,100}$)""",
    ]
    DupFields = ["location_area->location_building"]
  }
```