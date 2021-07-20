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
      """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
      """\sGenTime:\s{0,100}"({time}\d\d\d\d-\d\d-\d\d\s{1,100}\d{1,100}:\d\d:\d\d)\.\d{1,100}"""",
      """\sParam3:\s{0,100}"({badge_id}\d{1,100})"""",
      """\sName:\s{0,100}"({location_door}.+?)"""",
      """\sFirstName:\s{0,100}"({first_name}.+?)"""",
      """\sLastName:\s{0,100}"({last_name}.+?)"""",
      """({outcome}Access Granted)""",
    ]
  }
```