using System;

namespace Args;

[AttributeUsage(AttributeTargets.Field | AttributeTargets.Property, AllowMultiple = false)]
public class ArgsAttribute : Attribute
{
    /// <summary>
    /// The long version of the argument name. This field is required
    /// </summary>
    public string LongName { get; }
    /// <summary>
    /// The short version of the argument name (optional)
    /// </summary>
    public string ShortName { get; set; }
    /// <summary>
    /// If argument marked as Required, the application exits if user didn't supply this argument
    /// </summary>
    public bool Required { get; set; } = false;
    /// <summary>
    /// Short description to describe the argument purpose
    /// </summary>
    public string Description { get; set; } = null;
    /// <summary>
    /// Don't touch this property
    /// </summary>
    public bool IsSet { get; set; } = false;

    public ArgsAttribute(string longName)
    {
        LongName = longName;
    }
}
