TimeMachine <- function() {
  current_time <- 0
  
  travel <- function(years) {
    current_time <<- current_time + years
  }
  
  get_current_time <- function() {
    return(current_time)
  }
  
  return(list(travel = travel, get_current_time = get_current_time))
}

demonstrate_time_travel <- function() {
  time_machine <- TimeMachine()
  
  cat("Welcome to the Time Machine!\n")
  cat("Current time:", time_machine$get_current_time(), "\n")
  
  # Travel forward in time
  years_forward <- as.integer(readline("Enter the number of years to travel forward: "))
  time_machine$travel(years_forward)
  cat("Traveled forward in time by", years_forward, "years.\n")
  cat("Current time:", time_machine$get_current_time(), "\n")
  
  # Travel backward in time
  years_backward <- as.integer(readline("Enter the number of years to travel backward: "))
  time_machine$travel(-years_backward)
  cat("Traveled backward in time by", years_backward, "years.\n")
  cat("Current time:", time_machine$get_current_time(), "\n")
}

demonstrate_time_travel()