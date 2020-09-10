#### Parser Content
```Java
{
Name = q-picture-perfect-badge-access
  Vendor = PicturePerfect
  Product = PicturePerfect
  Lms = QRadar
  DataType = "physical-access"
  TimeFormat = "dd/MM/yyyy:HH:mm:ss z"
  Conditions = [ """<custom_condition_cont-6276>""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"(|({badge_id}[^\|"]+))\|(|({user_lastname}[^\|]+))\|(|({user_firstname}[^\|]+))\|(|({location_building}[^\|]+))\|(|({location_door}[^\|]+))\|(|({outcome}[^\|]+))\|({time}\d+\/\d+\/\d+\d+:\d+:\d+:\d+\s+\w+)\|""",
  ]
}
```