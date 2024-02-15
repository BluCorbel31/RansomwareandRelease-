class TimeMachine {
    constructor() {
        this.current_time = 0;
    }

    travel(years) {
        this.current_time += years;
    }

    getCurrentTime() {
        return this.current_time;
    }
}

function demonstrateTimeTravel() {
    const timeMachine = new TimeMachine();

    console.log("Welcome to the Time Machine!");
    console.log("Current time:", timeMachine.getCurrentTime());

    // Travel forward in time
    const yearsForward = parseInt(prompt("Enter the number of years to travel forward: "));
    timeMachine.travel(yearsForward);
    console.log("Traveled forward in time by", yearsForward, "years.");
    console.log("Current time:", timeMachine.getCurrentTime());

    // Travel backward in time
    const yearsBackward = parseInt(prompt("Enter the number of years to travel backward: "));
    timeMachine.travel(-yearsBackward);
    console.log("Traveled backward in time by", yearsBackward, "years.");
    console.log("Current time:", timeMachine.getCurrentTime());
}

demonstrateTimeTravel();