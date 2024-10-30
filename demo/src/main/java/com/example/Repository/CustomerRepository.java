package com.example.Repository;
import org.springframework.data.jpa.repository.JpaRepository;
import com.example.Model.Customer;

public interface CustomerRepository extends JpaRepository<Customer, Long>{

}
