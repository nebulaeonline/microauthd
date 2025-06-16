using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace mad.Common;

internal static class ConsoleUtils
{
    /// <summary>
    /// Reads user input from the console while masking the input with asterisks.
    /// </summary>
    /// <remarks>This method captures input character by character, displaying an asterisk (*) for
    /// each character entered. Backspace is supported, allowing the user to delete the last entered character.
    /// Input is terminated when the Enter key is pressed.</remarks>
    /// <returns>A <see cref="string"/> containing the user's input, excluding the masking asterisks.</returns>
    public static string ReadHiddenInput()
    {
        var result = new StringBuilder();
        ConsoleKeyInfo key;
        while ((key = Console.ReadKey(intercept: true)).Key != ConsoleKey.Enter)
        {
            if (key.Key == ConsoleKey.Backspace && result.Length > 0)
            {
                result.Length--;
                Console.Write("\b \b");
            }
            else if (!char.IsControl(key.KeyChar))
            {
                result.Append(key.KeyChar);
                Console.Write("*");
            }
        }
        Console.WriteLine();
        return result.ToString();
    }
}
