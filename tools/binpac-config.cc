///
/// Outputs paths and flags for using BinPAC++.
///
/// TODO: Currently we do not support installation outside of the built-tree
/// and all values returned here are thus in-tree.
///

#include <iostream>
#include <list>
#include <sstream>
#include <string>

#include <util/util.h>

#include <autogen/binpac-config.h>

using namespace std;

void usage()
{
    std::cerr << R"(
Usage: binpac-config [options]

== General options.

    --distbase              Print path of the BinPAC++ source distribution.
    --prefix                Print path of installation (TODO: same as --distbase currently)
    --version               Print BinPAC++ version.
    --help                  Print this usage summary

== Options controlling what to include in output.

    --compiler              Output flags for integrating the C++ compilers into host applications.
    --runtime               Output flags for integrating the C runtime libraries into host applications.

    --debug                 Output flags for working with debugging versions.

== Compiler and linker flags

    --cflags                Print flags for C compiler (--runtime only).
    --cxxflags              Print flags for C++ compiler.
    --ldflags               Print flags for linker.
    --libs                  Print libraries for linker.
    --libs-shared           Print shared libraries for linker.
    --libfiles-static       Print fully qualified paths to all static libraries.

== Options for running the command-line compilers.

    --binpac++-binary       Print the full path to the binpac++ binary.
    --binpac++-libdirs      Print standard BinPAC++ library directories.
    --binpac++-runtime-libs Print the full path of the BinPAC++ run-time library.

Example: binpac-config --compiler --cxxflags --debug

)";
}

void printList(stringstream& out, const std::list<string>& l)
{
    out << util::strjoin(l, " ") << " ";
}

void appendList(std::list<string>* dst, const std::list<string>& l, const string& prefix = "")
{
    for ( auto i : l )
        dst->push_back(prefix + i);
}

void appendList(std::list<string>* dst, const string& s, const string& prefix = "")
{
    dst->push_back(prefix + s);
}

void appendListFile(std::list<string>* dst, const string& s, const std::list<string>& search_paths,
                    const string& prefix = "", const string& postfix = "")
{
    auto base = prefix + s + postfix;

    auto path = ::util::findInPaths(base, search_paths);

    if ( path.size() == 0 ) {
        std::cerr << "warning: cannot find library " << s << std::endl;
        return;
    }

    dst->push_back(path);
}

void appendListFile(std::list<string>* dst, const std::list<string>& l,
                    const std::list<string>& search_paths, const string& prefix = "",
                    const string& postfix = "")
{
    for ( auto i : l )
        appendListFile(dst, i, search_paths, prefix, postfix);
}

int main(int argc, char** argv)
{
    bool want_compiler = false;
    bool want_runtime = false;
    bool want_debug = false;

    std::list<string> cflags;
    std::list<string> cxxflags;
    std::list<string> ldflags;
    std::list<string> libs;
    std::list<string> libs_shared;
    std::list<string> libfiles_static;

    std::list<string> options;

    // First pass over arguments: look for control options.

    for ( int i = 1; i < argc; i++ ) {
        string opt = argv[i];

        if ( opt == "--help" || opt == "-h" ) {
            usage();
            return 0;
        }

        if ( opt == "--compiler" ) {
            want_compiler = true;
            continue;
        }

        if ( opt == "--runtime" ) {
            want_runtime = true;
            continue;
        }

        if ( opt == "--debug" ) {
            want_debug = true;
            continue;
        }

        options.push_back(opt);
    }

    auto binpac_config = binpac::configuration();

    if ( want_compiler ) {
        appendList(&cflags, binpac_config.compiler_include_dirs, "-I");
        appendList(&cflags, binpac_config.compiler_cflags);
        appendList(&cxxflags, binpac_config.compiler_include_dirs, "-I");
        appendList(&cxxflags, binpac_config.compiler_cxxflags);
        appendList(&ldflags, binpac_config.compiler_ldflags);
        appendList(&libs, binpac_config.compiler_static_libraries, "-l");
        appendList(&libs, binpac_config.compiler_shared_libraries, "-l");
        appendList(&libs_shared, binpac_config.compiler_shared_libraries, "-l");
        appendListFile(&libfiles_static, binpac_config.compiler_static_libraries,
                       binpac_config.compiler_library_dirs, "lib", ".a");
    }

    if ( want_runtime ) {
        appendList(&cflags, binpac_config.runtime_cflags);
        appendList(&cflags, binpac_config.runtime_include_dirs, "-I");
        appendList(&cxxflags, binpac_config.runtime_cxxflags);
        appendList(&cxxflags, binpac_config.runtime_include_dirs, "-I");
        appendList(&ldflags, binpac_config.runtime_ldflags);

        if ( want_debug ) {
            appendList(&libs, binpac_config.runtime_library_bca_dbg);
            appendList(&libfiles_static, binpac_config.runtime_library_bca_dbg);
        }

        else {
            appendList(&libs, binpac_config.runtime_library_bca);
            appendList(&libfiles_static, binpac_config.runtime_library_bca);
        }

        appendList(&libs, binpac_config.runtime_shared_libraries, "-l");
        appendList(&libs_shared, binpac_config.runtime_shared_libraries, "-l");
    }

    bool need_component = false;
    stringstream out;
    stringstream lout;

    for ( auto opt : options ) {
        if ( opt == "--distbase" ) {
            out << binpac_config.distbase << std::endl;
            continue;
        }

        if ( opt == "--prefix" ) {
            out << binpac_config.prefix << std::endl;
            continue;
        }

        if ( opt == "--version" ) {
            out << "BinPAC++ " << binpac_config.version << std::endl;
            continue;
        }

        if ( opt == "--cflags" ) {
            need_component = true;
            printList(lout, cflags);
            continue;
        }

        if ( opt == "--cxxflags" ) {
            need_component = true;
            printList(lout, cxxflags);
            continue;
        }

        if ( opt == "--ldflags" ) {
            need_component = true;
            printList(lout, ldflags);
            continue;
        }

        if ( opt == "--libs" ) {
            need_component = true;
            printList(lout, libs);
            continue;
        }

        if ( opt == "--libs-shared" ) {
            need_component = true;
            printList(lout, libs_shared);
            continue;
        }

        if ( opt == "--libfiles-static" ) {
            need_component = true;
            printList(lout, libfiles_static);
            continue;
        }

        if ( opt == "--binpac++-binary" ) {
            out << binpac_config.path_binpacxx << std::endl;
            continue;
        }

        if ( opt == "--binpac++-libdirs" ) {
            printList(lout, binpac_config.binpac_library_dirs);
            continue;
        }

        if ( opt == "--binpac++-runtime-libs" ) {
            if ( want_debug )
                out << binpac_config.runtime_library_bca_dbg << std::endl;
            else
                out << binpac_config.runtime_library_bca << std::endl;
            continue;
        }

        std::cerr << "binpac-config: unknown option " << opt << "; use --help to see list."
                  << std::endl;
        return 1;
    }

    if ( need_component && ! (want_compiler || want_runtime) ) {
        cerr << "binpac-config: Either --compiler or --runtime (or both) must be given when "
                "printing flags."
             << std::endl;
        return 1;
    }

    cout << out.str();

    if ( lout.str().size() )
        cout << lout.str() << std::endl;

    return 0;
}