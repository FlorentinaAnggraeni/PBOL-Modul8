package com.example.Repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.example.Model.Product;

public interface ProductRepository extends JpaRepository<Product, Long>  {

}
