#### Parser Content
```Java
{
Name = cef-4724
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = ArcSight
    DataType = "windows-password-reset"
    TimeFormat = "epoch"
    Conditions = [ "externalId=4724 ", """An attempt was made to reset an account's password."""]
    Fields = [ """\sdhost=({host}[^\s]{1,2000})""",
      """({event_name}An attempt was made to reset an account's password)""",
        """Microsoft-Windows-Security-Auditing:({event_code}\d{4})""",
        """\srt=({time}\d{1,100})""",
        """\ssntdom=({domain}[^\s]{1,2000})""",
        """\ssuser=({user}.+?)\s{1,100}\w+=""",
        """\sduser=({target_user}.+?)\s{1,100}\w+=""",
        """\ssuid=({logon_sid}[^\s]{1,2000})"""
        """Security_,ID=({user_sid}[^\s]{1,2000}?)(\s|\||$)""",
        """\sdntdom=({target_domain}.+?)\s{1,100}\w+=""",
    ]
    DupFields = [ "host->dest_host" ]
    


}
```