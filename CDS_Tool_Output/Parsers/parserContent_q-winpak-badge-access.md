#### Parser Content
```Java
{
Name = q-winpak-badge-access
    Vendor = Honeywell WIN-PAK
  Product = Honeywell WIN-PAK
    Lms = QRadar
    DataType = "physical-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["""Winpak - Access Granted""", """ Name:""", """ FirstName:""", """ LastName:"""]
    Fields = [
      """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
      """\sGenTime:\s*"({time}\d\d\d\d-\d\d-\d\d\s+\d+:\d\d:\d\d)\.\d+"""",
      """\sParam3:\s*"({badge_id}\d+)"""",
      """\sName:\s*"({location_door}.+?)"""",
      """\sFirstName:\s*"({first_name}.+?)"""",
      """\sLastName:\s*"({last_name}.+?)"""",
      """({outcome}Access Granted)""",
    ]
  }
```