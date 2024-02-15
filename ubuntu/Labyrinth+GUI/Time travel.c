#include <stdio.h>

struct TimeMachine {
    int current_time;
};

void travel(struct TimeMachine *time_machine, int years) {
    time_machine->current_time += years;
}

int get_current_time(struct TimeMachine *time_machine) {
    return time_machine->current_time;
}

void demonstrate_time_travel() {
    struct TimeMachine time_machine = { .current_time = 0 };

    printf("Welcome to the Time Machine!\n");
    printf("Current time: %d\n", get_current_time(&time_machine));

    // Travel forward in time
    printf("Enter the number of years to travel forward: ");
    int years_forward;
    scanf("%d", &years_forward);
    travel(&time_machine, years_forward);
    printf("Traveled forward in time by %d years.\n", years_forward);
    printf("Current time: %d\n", get_current_time(&time_machine));

    // Travel backward in time
    printf("Enter the number of years to travel backward: ");
    int years_backward;
    scanf("%d", &years_backward);
    travel(&time_machine, -years_backward);
    printf("Traveled backward in time by %d years.\n", years_backward);
    printf("Current time: %d\n", get_current_time(&time_machine));
}

int main() {
    demonstrate_time_travel();
    return 0;
}