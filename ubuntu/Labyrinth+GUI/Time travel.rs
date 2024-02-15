struct TimeMachine {
    current_time: i32,
}

impl TimeMachine {
    fn new() -> TimeMachine {
        TimeMachine { current_time: 0 }
    }

    fn travel(&mut self, years: i32) {
        self.current_time += years;
    }

    fn get_current_time(&self) -> i32 {
        self.current_time
    }
}

fn demonstrate_time_travel() {
    let mut time_machine = TimeMachine::new();

    println!("Welcome to the Time Machine!");
    println!("Current time: {}", time_machine.get_current_time());

    // Travel forward in time
    println!("Enter the number of years to travel forward: ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).expect("Failed to read input");
    let years_forward: i32 = input.trim().parse().expect("Invalid input");
    time_machine.travel(years_forward);
    println!("Traveled forward in time by {} years.", years_forward);
    println!("Current time: {}", time_machine.get_current_time());

    // Travel backward in time
    println!("Enter the number of years to travel backward: ");
    input.clear();
    std::io::stdin().read_line(&mut input).expect("Failed to read input");
    let years_backward: i32 = input.trim().parse().expect("Invalid input");
    time_machine.travel(-years_backward);
    println!("Traveled backward in time by {} years.", years_backward);
    println!("Current time: {}", time_machine.get_current_time());
}

fn main() {
    demonstrate_time_travel();
}