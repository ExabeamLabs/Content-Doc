#### Parser Content
```Java
{
Name = s-honeywell-physical-badge-access
    Vendor = Honeywell 
    Product = PROWATCH
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat = "MM/dd/yyyy HH:mm:ss"
    Conditions = [  """exabeam_sourcetype=honeywell:prowatch""" ]
    Fields = [
      """exabeam_raw=([^\|]*\|){9}({time}[^\|]+)\|""",
      """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
      """exabeam_raw=([^\|])({employee_id}[^\|]+)\|""",
      """exabeam_raw=([^\|]*\|){2}({last_name}[^\|]+)\|""",
      """exabeam_raw=([^\|]*\|){3}({first_name}[^\|]+)\|""",
      """exabeam_raw=([^\|]*\|){4}({middle_name}[^\|]+)\|""",
      """exabeam_raw=([^\|]*\|){8}({badge_id}[^\|]+)\|""",
      """exabeam_raw=([^\|]*\|){10}({outcome}[^\|]+)\|""",
      """exabeam_raw=([^\|]*\|){11}({location_door}[^\|]+)\|""",
      """exabeam_raw=([^\|]*\|){13}({location_area}[^\|]+?)(\||\s*$)""",
    ]
    DupFields = ["location_area->location_building"]
  }
```