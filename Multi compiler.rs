use std::process::Command;
use std::fs;
use python_shell::{Python, Context};

// Compiler: Compile code for a specific language
fn compile_code(language: &str, code: &str) -> String {
    match language {
        "c" => compile_c(code),
        "csharp" => compile_csharp(code),
        "javascript" => compile_javascript(code),
        "r" => compile_r(code),
        "sql" => compile_sql(code),
        "rust" => compile_rust(code),
        // Add support for more languages as needed
        _ => panic!("Unsupported language: {}", language),
    }
}

// Compiler: Compile C code
fn compile_c(code: &str) -> String {
    // Write the C code to a temporary file
    let c_file = "temp.c";
    fs::write(c_file, code).expect("Failed to write C code to file");

    // Compile the C code using gcc
    let output = Command::new("gcc")
        .arg("-o")
        .arg("temp")
        .arg(c_file)
        .output()
        .expect("Failed to compile C code");

    // Return the compiler output (stdout/stderr)
    format!(
        "Compiler output:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

// Compiler: Compile C# code
fn compile_csharp(code: &str) -> String {
    // Write the C# code to a temporary file
    let cs_file = "temp.cs";
    fs::write(cs_file, code).expect("Failed to write C# code to file");

    // Compile the C# code using csc (C# compiler)
    let output = Command::new("csc")
        .arg("/out:temp.exe")
        .arg(cs_file)
        .output()
        .expect("Failed to compile C# code");

    // Return the compiler output (stdout/stderr)
    format!(
        "Compiler output:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

// Compiler: Compile JavaScript code
fn compile_javascript(code: &str) -> String {
    // JavaScript is interpreted, no compilation needed
    execute_javascript(code)
}

// Compiler: Compile R code
fn compile_r(code: &str) -> String {
    // R is interpreted, no compilation needed
    execute_r(code)
}

// Compiler: Compile SQL code
fn compile_sql(code: &str) -> String {
    // SQL is interpreted, no compilation needed
    execute_sql(code)
}

// Compiler: Compile Rust code
fn compile_rust(code: &str) -> String {
    // Write the Rust code to a temporary file
    let rust_file = "temp.rs";
    fs::write(rust_file, code).expect("Failed to write Rust code to file");

    // Compile the Rust code using rustc (Rust compiler)
    let output = Command::new("rustc")
        .arg("-o")
        .arg("temp")
        .arg(rust_file)
        .output()
        .expect("Failed to compile Rust code");

    // Return the compiler output (stdout/stderr)
    format!(
        "Compiler output:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

// Execute Python code
fn execute_python(code: &str) -> String {
    let mut python = Python::new();
    let context = Context::new();

    // Execute the Python code
    let result = python
        .run_with_context(&context, code)
        .expect("Failed to execute Python code");

    // Return the result
    result.stdout
}

// Execute JavaScript code
fn execute_javascript(code: &str) -> String {
    // Execute JavaScript code using node
    let output = Command::new("node")
        .arg("-e")
        .arg(code)
        .output()
        .expect("Failed to execute JavaScript code");

    // Return the output
    String::from_utf8_lossy(&output.stdout).to_string()
}

// Execute R code
fn execute_r(code: &str) -> String {
    // Write the R code to a temporary file
    let r_file = "temp.R";
    fs::write(r_file, code).expect("Failed to write R code to file");

    // Execute the R code using Rscript
    let output = Command::new("Rscript")
        .arg(r_file)
        .output()
        .expect("Failed to execute R code");

    // Return the output
    String::from_utf8_lossy(&output.stdout).to_string()
}

// Execute SQL code
fn execute_sql(code: &str) -> String {
    // SQL code execution logic goes here
    // This function will depend on how you plan to execute SQL code (e.g., through a database connection)
    // For demonstration purposes, let's just print the SQL code
    println!("Executing SQL code:\n{}", code);
    "SQL code executed".to_string()
}

fn main() {
    let c_input = r#"
        #include <stdio.h>
        int main() {
            printf("Hello from C!\n");
            return 0;
        }
    "#;

    let c_compiler_output = compile_code("c", c_input);
    println!("C Compiler Output:\n{}", c_compiler_output);

    let csharp_input = r#"
        using System;
        class Program {
            static void Main(string[] args) {
                Console.WriteLine("Hello from C#!");
            }
        }
    "#;

    let csharp_compiler_output = compile_code("csharp", csharp_input);
    println!("C# Compiler Output:\n{}", csharp_compiler_output);

    let javascript_input = r#"
        console.log("Hello from JavaScript!");
    "#;

    let javascript_output = compile_code("javascript", javascript_input);
    println!("JavaScript Output:\n{}", javascript_output);

    let r_input = r#"
        cat("\nHello from R!\n")
    "#;

    let r_output = compile_code("r", r_input);
    println!("R Output:\n{}", r_output);

    let sql_input = "SELECT * FROM table;";
    let sql_output = compile_code("sql", sql_input);
    println!("SQL Output:\n{}", sql_output);

    let rust_input = r#"
        fn main() {
            println!("Hello from Rust!");
        }
    "#;

    let rust_compiler_output = compile_code("rust", rust_input);
    println!("Rust Compiler Output:\n{}", rust_compiler_output);

    let python_input = r#"
        print("Hello from Python!")
    "#;

    let python_output = execute_python(python_input);
    println!("Python output:\n{}", python_output);
}