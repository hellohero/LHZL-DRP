package com.lhzl.drp.dao;

import com.lhzl.drp.model.Permissioninfo;

public interface PermissioninfoMapper {
    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table tbl_permissioninfo
     *
     * @mbggenerated Thu Mar 24 15:33:09 CST 2016
     */
    int deleteByPrimaryKey(Long pmsnid);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table tbl_permissioninfo
     *
     * @mbggenerated Thu Mar 24 15:33:09 CST 2016
     */
    int insert(Permissioninfo record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table tbl_permissioninfo
     *
     * @mbggenerated Thu Mar 24 15:33:09 CST 2016
     */
    int insertSelective(Permissioninfo record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table tbl_permissioninfo
     *
     * @mbggenerated Thu Mar 24 15:33:09 CST 2016
     */
    Permissioninfo selectByPrimaryKey(Long pmsnid);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table tbl_permissioninfo
     *
     * @mbggenerated Thu Mar 24 15:33:09 CST 2016
     */
    int updateByPrimaryKeySelective(Permissioninfo record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table tbl_permissioninfo
     *
     * @mbggenerated Thu Mar 24 15:33:09 CST 2016
     */
    int updateByPrimaryKeyWithBLOBs(Permissioninfo record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table tbl_permissioninfo
     *
     * @mbggenerated Thu Mar 24 15:33:09 CST 2016
     */
    int updateByPrimaryKey(Permissioninfo record);
}