#### Parser Content
```Java
{
Name = oracle-avdf-database-login
  DataType = "database-login"
  Conditions = [  """TARGET_TYPE="USER"""", """ EVENT_NAME="LOGIN SUCCEEDED"""", """ COMMAND_CLASS="LOGIN"""", """ SECURED_TARGET_NAME="""  ]
}
```