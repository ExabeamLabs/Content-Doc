#### Parser Content
```Java
{
Name = cef-4663
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-4663"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft|Microsoft Windows|""","""|Microsoft-Windows-Security-Auditing:4663|""" ]
  Fields = [ """exabeam_EventTime=({eventtime}\d{1,100})""",
    """({event_name}An attempt was made to access an object)""",
    """\sexternalId=({event_code}\d{1,100})""",
    """\srt=({time}\d{1,100})""",
    """\sdntdom=({domain}[^\s]+)""",
    """\sduser=({user}.+?)\s{1,100}\w+=""",
    """\sduid=({logon_id}[^\s]+)""",
    """\scs1=({accesses}.+?)\s{1,100}\w+=""",
    """\sdvc=({host}[a-fA-F:\d.]+)""",
    """\sdvchost=({host}[^\s]+)""",
    """\sfname=({file_path}.+?)\s{1,100}(?:$|\w+=)""",
    """\sfname=({file_parent}.+?)\\+(?:[^\\=]+?)\s{1,100}(?:$|\w+=)""",
    """\sfname=[^=]*\\({file_name}.*?({file_ext}\.[^\\:\s.]+)?)\s{1,100}(?:$|\w+=)""",
    """\scs3=({access_mask}\w+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```