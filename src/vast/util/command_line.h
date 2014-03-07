#ifndef VAST_UTIL_COMMAND_LINE_H
#define VAST_UTIL_COMMAND_LINE_H

#include <map>
#include <vector>
#include "vast/util/editline.h"
#include "vast/util/intrusive.h"
#include "vast/util/result.h"

namespace vast {
namespace util {

/// An abstraction for a mode-based command line interace (CLI). The CLI offers
/// multiple *modes* each of which contain a set of *commands*. At any given
/// time, one can change the mode of the command line by pushing or popping a
/// mode from the mode stack. Each mode has a distinct prompt and command
/// history. A command is a recursive element consisting of zero or more
/// space-separated sub-commands. Each command has a description and a callback
/// handler for arguments which themselves are not commands.
class command_line
{
public:
  /// The callback function for command arguments.
  /// The string argument represents the argument of the command.
  /// The return value indicates whether the callback succeeded.
  using callback = std::function<result<bool>(std::string)>;

  class mode;

  /// A representation of command with zero or more arguments.
  class command : intrusive_base<command>
  {
    command(command const&) = delete;
    command& operator=(command const&) = delete;

  public:
    /// Constructs a command.
    /// @param mode The mode this command exists in.
    /// @param name The parent command.
    /// @param name The name of the command.
    /// @param desc A one-line description of the command for the help.
    /// @pre `mode`
    command(intrusive_ptr<mode> mode,
            intrusive_ptr<command> parent,
            std::string name,
            std::string desc);

    /// Adds a sub-command to this command.
    /// @param name The name of the command.
    /// @param desc A one-line description of the command.
    /// @returns If successful, a valid pointer to the newly created command.
    intrusive_ptr<command> add(std::string name, std::string desc);

    /// Assigns a callback handler for arguments to this command.
    /// @param f The function to execute for the command arguments.
    void on(callback f);

    /// Execute a command line.
    result<bool> execute(std::string args) const;

    /// Retrieves the name of this very command.
    /// @returns The name of this command.
    std::string const& name() const;

    /// Retrieves the absolute name of the path from the root command.
    /// @returns A space-separted command sequence.
    std::string absolute_name() const;

    /// Retrieves the autogenerated help string for this command.
    /// @param indent The number of spaces to indent the help text.
    /// @returns The help string for this command.
    std::string help(size_t indent = 0) const;

  private:
    intrusive_ptr<mode> mode_;
    intrusive_ptr<command> parent_;
    std::vector<intrusive_ptr<command>> commands_;
    std::string name_;
    std::string description_;
    callback handler_;
  };

  /// A command-line context with its own commands, history, and prompt.
  class mode : intrusive_base<mode>
  {
    friend command_line;

    mode(mode const&) = delete;
    mode& operator=(mode const&) = delete;

  public:
    /// Constructs a mode.
    /// @param name The name of the mode.
    /// @param prompt The prompt string.
    /// @param prompt_color The color of *prompt*.
    /// @param history_file The file where to store the mode history.
    mode(std::string name, std::string prompt, char const* prompt_color, std::string history_file);

    /// Adds a sub-command to this command.
    /// @param name The name of the command.
    /// @param desc A one-line description of the command.
    /// @returns If successful, a valid pointer to the newly created command.
    intrusive_ptr<command> add(std::string name, std::string desc);

    /// Assigns a callback handler for unknown commands.
    /// @param f The function to execute for unknown commands.
    void on_unknown_command(callback f);

    /// Assigns a callback handler for unknown commands.
    /// @param f The function to execute for unknown commands.
    void on_complete(editline::completer::callback f);

    /// Registers a completion with this mode.
    /// @param The string to register.
    void complete(std::string str);

    /// Replaces the completions associated with a set of new ones.
    /// @param completiosn The new completions.
    void complete(std::vector<std::string> completions);

    /// Execute a command line.
    result<bool> execute(std::string args) const;

    /// Retrieves the name of this mode.
    /// @returns The name of this mode
    std::string const& name() const;

    /// Retrieves the autogenerated help string for this mode.
    /// @param indent The number of spaces to indent the help text.
    /// @returns The help string for this mode.
    std::string help(size_t indent = 0) const;

  private:
    intrusive_ptr<command> root_;
    editline::history history_;
    editline el_;
  };

  /// Creates a new mode for a set of related commands. Only one mode can
  /// be active at a time. Each mode has its own history.
  ///
  /// @param name The name of the mode.
  ///
  /// @param prompt The prompt of the mode.
  ///
  /// @param prompt_color The color of *prompt*.
  ///
  /// @param history_file The filename of the history.
  ///
  /// @returns A valid pointer to the new mode on success.
  intrusive_ptr<mode> mode_add(std::string name,
                               std::string prompt,
                               char const* prompt_color = nullptr,
                               std::string history_file = "");

  /// Removes an existing mode.
  /// @param name The name of the mode.
  /// @returns `true` on success.
  bool mode_rm(std::string const& name);

  /// Enters a given mode.
  /// @param mode The name of mode.
  /// @returns `true` on success.
  bool mode_push(std::string const& mode);

  /// Leaves the current mode.
  /// @returns `true` on success.
  bool mode_pop();

  /// Appends an entry to the history of the current mode.
  /// @param entry The history entry to add.
  /// @returns `true` on success.
  bool append_to_history(std::string const& entry);

  /// Processes a single command from the command line.
  /// @param cmd The command to process.
  /// @returns A valid result if the callback executed and an error on failure.
  result<bool> process(std::string cmd);

  /// Retrieves a single character from the command line in a blocking fashion.
  /// @param c The result parameter containing the character from STDIN.
  /// @returns `true` on success.
  bool get(char& c);

  /// Retrieves a full line from the command line in a blocking fashion.
  /// @param line The result parameter containing the line.
  /// @returns `true` on success.
  bool get(std::string& line);

private:
  std::vector<intrusive_ptr<mode>> mode_stack_;
  std::map<std::string, intrusive_ptr<mode>> modes_;
};

} // namespace util
} // namespace vast

#endif
