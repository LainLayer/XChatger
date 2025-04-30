
#run,stallable build();
build :: () {
    set_build_options_dc(.{do_output=false});
    options := get_build_options();

    w := compiler_create_workspace("Main program");

    options.output_type            = .EXECUTABLE;
    options.output_executable_name = "main";
    set_build_options(options, w);

    compiler_begin_intercept(w);
    add_build_file("main.jai", w);
    compiler_end_intercept(w);
}

#import "Compiler";
